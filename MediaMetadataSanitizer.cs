using System.Buffers.Binary;
using System.Text;
using ImageMagick;

internal sealed class MediaSanitizationException(string message, Exception? innerException = null)
    : Exception(message, innerException);

internal sealed record MediaSanitizationResult(
    string ContentType,
    string? StorageExtension);

/// <summary>
/// Removes privacy-sensitive metadata before a public media path is published.
///
/// Still JPEG, PNG, WebP and AVIF images are decoded and re-encoded before a
/// format-specific structural pass. This both proves that the compressed pixels are
/// decodable and guarantees that metadata not understood by the structural parser is
/// not copied to the public asset. Animated image payloads are decoded and re-encoded
/// without flattening, while their frame count and cumulative decoded size remain
/// bounded. Audio and video payloads retain the existing bounded container scrubbers.
/// Unsupported media containers fail closed instead of being copied unchanged.
/// </summary>
internal static class MediaMetadataSanitizer
{
    private const int MaxContainerDepth = 16;
    private const int MaxConcurrentMediaSanitizers = 2;
    private const int MaxAnimationFrames = 1_000;
    private const ulong HardMaxMagickMemoryBytes = 256UL * 1024 * 1024;
    private const ulong HardMaxMagickProfileBytes = 2UL * 1024 * 1024;
    private static readonly byte[] ZeroBuffer = new byte[64 * 1024];
    private static readonly SemaphoreSlim MediaSanitizerSlots = new(
        MaxConcurrentMediaSanitizers,
        MaxConcurrentMediaSanitizers);
    private static readonly Lazy<bool> MagickResourceConfiguration = new(
        ConfigureMagickResources,
        LazyThreadSafetyMode.ExecutionAndPublication);

    private static bool ConfigureMagickResources()
    {
        // These are process-wide ImageMagick limits. Per-request pixel and byte limits
        // are checked before Read/ToByteArray as well; the native limits are a second
        // guard against a decoder allocation race or an unrecognised delegate path.
        ResourceLimits.Memory = HardMaxMagickMemoryBytes;
        ResourceLimits.MaxMemoryRequest = HardMaxMagickMemoryBytes;
        ResourceLimits.Disk = 0;
        ResourceLimits.Area = 50_000_000;
        ResourceLimits.Width = 16_384;
        ResourceLimits.Height = 16_384;
        ResourceLimits.ListLength = MaxAnimationFrames;
        ResourceLimits.Thread = MaxConcurrentMediaSanitizers;
        ResourceLimits.Time = 60;
        ResourceLimits.MaxProfileSize = HardMaxMagickProfileBytes;
        return true;
    }

    private static void EnsureMagickResources()
    {
        try
        {
            _ = MagickResourceConfiguration.Value;
        }
        catch (Exception exception) when (exception is not MediaSanitizationException)
        {
            throw new MediaSanitizationException(
                "The bounded image decoder is unavailable.",
                exception);
        }
    }

    private static readonly HashSet<string> PngPreservedAncillaryChunks = new(StringComparer.Ordinal)
    {
        // Rendering and animation records. Text, EXIF, time, ICC and unknown/private
        // ancillary chunks are intentionally omitted.
        "tRNS", "gAMA", "cHRM", "sRGB", "bKGD", "acTL", "fcTL", "fdAT"
    };

    private static readonly HashSet<string> WebpPayloadChunks = new(StringComparer.Ordinal)
    {
        "VP8 ", "VP8L", "VP8X", "ALPH", "ANIM", "ANMF"
    };

    private static readonly HashSet<string> IsoContainerBoxes = new(StringComparer.Ordinal)
    {
        "moov", "trak", "mdia", "minf", "dinf", "stbl", "edts", "moof", "traf", "mfra"
    };

    private static readonly HashSet<string> IsoMetadataBoxes = new(StringComparer.Ordinal)
    {
        "udta", "meta", "uuid", "ilst", "keys", "loci", "\u00A9xyz", "\u00A9day", "\u00A9nam",
        "\u00A9ART", "\u00A9too", "name", "free", "skip", "wide"
    };

    private static readonly HashSet<string> IsoAllowedLeafBoxes = new(StringComparer.Ordinal)
    {
        "ftyp", "styp", "mdat", "mvhd", "tkhd", "mdhd", "hdlr", "vmhd", "smhd", "hmhd", "nmhd",
        "dref", "url ", "urn ", "stsd", "stts", "ctts", "cslg", "stsc", "stsz", "stz2", "stco",
        "co64", "stss", "stsh", "padb", "stdp", "sdtp", "sbgp", "sgpd", "subs", "elst", "mehd",
        "trex", "mfhd", "tfhd", "trun", "tfdt", "saiz", "saio", "senc", "pssh", "sidx", "ssix",
        "prft", "emsg", "mfro", "tfra", "pdin", "iods", "kind", "elng", "clap", "pasp", "colr",
        "gama", "fiel", "chan", "btrt"
    };

    private static readonly HashSet<ulong> EbmlSensitiveElements =
    [
        0x4461,     // DateUTC
        0x7BA9,     // Title
        0x4D80,     // MuxingApp
        0x5741,     // WritingApp
        0x73A4,     // SegmentUID
        0x7384,     // SegmentFilename
        0x3CB923,   // PrevUID
        0x3C83AB,   // PrevFilename
        0x3EB923,   // NextUID
        0x3E83BB,   // NextFilename
        0x536E,     // Track name
        0x258688,   // CodecName
        0x3A9697,   // CodecSettings
        0x3B4040,   // CodecInfoURL
        0x26B240,   // CodecDownloadURL
        0x4444,     // SegmentFamily
        0xEC,       // Void (may contain arbitrary residual bytes)
        0xBF        // CRC-32 (invalid after mutation; replace with Void)
    ];

    private static readonly HashSet<ulong> EbmlSensitiveMasterElements =
    [
        0x1254C367, // Tags
        0x1941A469, // Attachments
        0x1043A770, // Chapters
        0x6924      // ChapterTranslate
    ];

    private static readonly HashSet<ulong> EbmlTraversedMasterElements =
    [
        0x1549A966, // Info
        0x1654AE6B, // Tracks
        0xAE,       // TrackEntry
        0xE0,       // Video
        0xE1,       // Audio
        0x6D80,     // ContentEncodings
        0x6240,     // ContentEncoding
        0x5034,     // ContentCompression
        0x5035,     // ContentEncryption
        0x47E7,     // ContentEncAESSettings
        0x55B0,     // Colour
        0x55D0,     // MasteringMetadata
        0x7670,     // Projection
        0x41E4,     // BlockAdditionMapping
        0x6624      // TrackTranslate
    ];

    private static readonly HashSet<ulong> EbmlAllowedNestedLeafElements =
    [
        0x2AD7B1, 0x4489, // TimecodeScale, Duration
        0xD7, 0x73C5, 0x83, 0xB9, 0x88, 0x55AA, 0x55AB, 0x55AC, 0x55AD, 0x55AE, 0x55AF,
        0x9C, 0x6DE7, 0x6DF8, 0x23E383, 0x234E7A, 0x23314F, 0x537F, 0x55EE,
        0x86, 0x63A2, 0x56AA, 0x56BB, 0x22B59C, 0x22B59D, 0x25FDBD,
        0x9A, 0x9D, 0x53B8, 0x53C0, 0x53B9, 0xB0, 0xBA, 0x54AA, 0x54BB, 0x54CC, 0x54DD,
        0x54B0, 0x54BA, 0x54B2, 0x54B3,
        0xB5, 0x78B5, 0x9F, 0x7D7B, 0x6264, 0x52F1,
        0x6A, 0x5031, 0x5032, 0x5033, 0x4254, 0x4255, 0x47E1, 0x47E2, 0x47E8,
        0x47E9, 0x47EA, 0x47EB, 0x47EC, 0x47ED,
        0x55B1, 0x55B2, 0x55B3, 0x55B4, 0x55B5, 0x55B6, 0x55B7, 0x55B8, 0x55B9, 0x55BA, 0x55BB,
        0x55BC, 0x55BD, 0x55D1, 0x55D2, 0x55D3, 0x55D4, 0x55D5, 0x55D6, 0x55D7, 0x55D8,
        0x7671, 0x7672, 0x7673, 0x7674, 0x7675, 0x7676,
        0x41F0, 0x41A4, 0x41E7, 0x41ED, 0x41F7, 0x41E6, 0x66FC, 0x66BF, 0x66A5
    ];

    private static readonly HashSet<ulong> EbmlSegmentElements =
    [
        0x114D9B74, // SeekHead
        0x1549A966, // Info
        0x1F43B675, // Cluster
        0x1654AE6B, // Tracks
        0x1C53BB6B, // Cues
        0x1941A469, // Attachments
        0x1043A770, // Chapters
        0x1254C367, // Tags
        0xEC,       // Void
        0xBF        // CRC-32
    ];

    private static readonly HashSet<ulong> EbmlHeaderElements =
    [
        0x4286, // EBMLVersion
        0x42F7, // EBMLReadVersion
        0x42F2, // EBMLMaxIDLength
        0x42F3, // EBMLMaxSizeLength
        0x4282, // DocType
        0x4287, // DocTypeVersion
        0x4285, // DocTypeReadVersion
        0xEC,   // Void
        0xBF    // CRC-32
    ];

    public static async Task<MediaSanitizationResult> SanitizeAsync(
        string contentType,
        string sourcePath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        return await SanitizeAsync(
            contentType,
            sourcePath,
            destinationPath,
            new UploadStorageOptions(),
            cancellationToken);
    }

    public static async Task<MediaSanitizationResult> SanitizeAsync(
        string contentType,
        string sourcePath,
        string destinationPath,
        UploadStorageOptions storageOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(storageOptions);
        var isMedia = contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) ||
                      contentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase) ||
                      contentType.StartsWith("audio/", StringComparison.OrdinalIgnoreCase);
        if (!isMedia)
        {
            await CopyFileAsync(sourcePath, destinationPath, cancellationToken);
            return new MediaSanitizationResult(contentType, null);
        }

        await MediaSanitizerSlots.WaitAsync(cancellationToken);
        try
        {
            switch (contentType.ToLowerInvariant())
            {
                case "image/jpeg":
                case "image/png":
                case "image/gif":
                case "image/webp":
                case "image/avif":
                    return await TranscodeStillOrRewriteAnimatedImageAsync(
                        contentType,
                        sourcePath,
                        destinationPath,
                        storageOptions,
                        cancellationToken);
                case "video/mp4":
                case "audio/mp4":
                    await CopyFileAsync(sourcePath, destinationPath, cancellationToken);
                    await ScrubIsoBaseMediaAsync(destinationPath, cancellationToken);
                    return new MediaSanitizationResult(contentType, null);
                case "audio/webm":
                    await CopyFileAsync(sourcePath, destinationPath, cancellationToken);
                    await ScrubWebmAsync(destinationPath, cancellationToken);
                    return new MediaSanitizationResult(contentType, null);
                default:
                    throw new MediaSanitizationException(
                        "This media container cannot be scrubbed safely.");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (MediaSanitizationException)
        {
            throw;
        }
        catch (MagickException exception)
        {
            throw new MediaSanitizationException(
                "Media metadata could not be removed safely.",
                exception);
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or UnauthorizedAccessException or OverflowException)
        {
            throw new MediaSanitizationException(
                "Media metadata could not be removed safely.",
                exception);
        }
        finally
        {
            MediaSanitizerSlots.Release();
        }
    }

    private static async Task<MediaSanitizationResult> TranscodeStillOrRewriteAnimatedImageAsync(
        string contentType,
        string sourcePath,
        string destinationPath,
        UploadStorageOptions options,
        CancellationToken cancellationToken)
    {
        EnsureMagickResources();
        var inputFormat = ResolveImageFormat(contentType);
        var readSettings = new MagickReadSettings { Format = inputFormat };
        using var metadata = new MagickImageCollection();
        metadata.Ping(sourcePath, readSettings);
        if (metadata.Count == 0 || metadata.Count > MaxAnimationFrames)
        {
            throw new MediaSanitizationException("Image frame count is outside the safe limit.");
        }
        ValidateImageCollectionGeometry(metadata, options);

        if (metadata.Count > 1)
        {
            return await TranscodeAnimatedImageAsync(
                contentType,
                sourcePath,
                destinationPath,
                inputFormat,
                readSettings,
                metadata.Count,
                options,
                cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var image = new MagickImage();
        await image.ReadAsync(sourcePath, readSettings, cancellationToken);
        ValidateImageGeometry(image.Width, image.Height, options);
        image.AutoOrient();
        ValidateImageGeometry(image.Width, image.Height, options);
        ResizeStillImageIfNeeded(image, options.MaxStoredImageDimension);
        var hasTransparency = !image.IsOpaque;
        image.Strip();
        image.ColorSpace = ColorSpace.sRGB;

        var output = ResolveStillOutput(contentType, hasTransparency, options.PreferredStillImageFormat);
        image.Format = output.Format;
        image.Quality = (uint)options.ImageLossyQuality;
        var encoded = image.ToByteArray(output.Format);
        if (encoded.Length == 0 || encoded.LongLength > UploadSecurity.MaxStandardUploadBytes)
        {
            throw new MediaSanitizationException("Image encoder produced an invalid output.");
        }

        var structurallySanitized = output.Format switch
        {
            MagickFormat.Jpeg => SanitizeJpeg(encoded),
            MagickFormat.Png => SanitizePng(encoded),
            MagickFormat.Gif => SanitizeGif(encoded),
            MagickFormat.WebP => SanitizeWebp(encoded),
            MagickFormat.Avif => encoded,
            _ => throw new MediaSanitizationException("Image output format is unsupported.")
        };
        if (structurallySanitized.Length == 0 ||
            structurallySanitized.LongLength > UploadSecurity.MaxStandardUploadBytes)
        {
            throw new MediaSanitizationException("Image output exceeds the safe file-size budget.");
        }

        try
        {
            await WriteNewFileAsync(destinationPath, structurallySanitized, cancellationToken);
            VerifyStillOutput(
                output.ContentType,
                destinationPath,
                image.Width,
                image.Height,
                options,
                cancellationToken);
        }
        catch
        {
            if (File.Exists(destinationPath))
            {
                File.Delete(destinationPath);
            }
            throw;
        }
        return new MediaSanitizationResult(output.ContentType, output.StorageExtension);
    }

    private static async Task<MediaSanitizationResult> TranscodeAnimatedImageAsync(
        string contentType,
        string sourcePath,
        string destinationPath,
        MagickFormat inputFormat,
        MagickReadSettings readSettings,
        int expectedFrameCount,
        UploadStorageOptions options,
        CancellationToken cancellationToken)
    {
        if (inputFormat == MagickFormat.Png)
        {
            // ImageMagick 7 in the pinned Magick.NET build decodes APNG but writes a
            // single PNG frame. Reject instead of silently destroying the animation.
            throw new MediaSanitizationException(
                "Animated PNG cannot be re-encoded without flattening frames.");
        }

        using var frames = new MagickImageCollection();
        await frames.ReadAsync(sourcePath, readSettings, cancellationToken);
        if (frames.Count != expectedFrameCount || frames.Count <= 1)
        {
            throw new MediaSanitizationException("Animated image frame count changed during decoding.");
        }
        ValidateImageCollectionGeometry(frames, options);

        foreach (var frame in frames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            frame.AutoOrient();
            ValidateImageGeometry(frame.Width, frame.Height, options);
            frame.Strip();
            frame.ColorSpace = ColorSpace.sRGB;
            frame.Format = inputFormat;
            frame.Quality = (uint)options.ImageLossyQuality;
        }
        ValidateImageCollectionGeometry(frames, options);

        var encoded = frames.ToByteArray(inputFormat);
        if (encoded.Length == 0 || encoded.LongLength > UploadSecurity.MaxStandardUploadBytes)
        {
            throw new MediaSanitizationException("Animated image encoder produced an invalid output.");
        }
        var sanitized = inputFormat switch
        {
            MagickFormat.Gif => SanitizeGif(encoded),
            MagickFormat.WebP => SanitizeWebp(encoded),
            MagickFormat.Avif => encoded,
            _ => throw new MediaSanitizationException("Animated image output format is unsupported.")
        };

        try
        {
            await WriteNewFileAsync(destinationPath, sanitized, cancellationToken);
            VerifyAnimatedOutput(
                contentType,
                destinationPath,
                frames.Count,
                options,
                cancellationToken);
        }
        catch
        {
            if (File.Exists(destinationPath))
            {
                File.Delete(destinationPath);
            }
            throw;
        }
        return UnchangedImageResult(contentType);
    }

    private static void ValidateImageCollectionGeometry(
        IEnumerable<IMagickImage<byte>> frames,
        UploadStorageOptions options)
    {
        ulong totalPixels = 0;
        var count = 0;
        foreach (var frame in frames)
        {
            ValidateImageGeometry(frame.Width, frame.Height, options);
            totalPixels = checked(totalPixels + ((ulong)frame.Width * frame.Height));
            count++;
        }
        if (count == 0 || count > MaxAnimationFrames ||
            totalPixels > (ulong)options.MaxAnimatedImageTotalPixels ||
            checked(totalPixels * 4UL) > (ulong)options.MaxDecodedImageBytes)
        {
            throw new MediaSanitizationException(
                "Animated image exceeds the cumulative pixel or memory budget.");
        }
    }

    private static void ValidateImageGeometry(
        uint width,
        uint height,
        UploadStorageOptions options)
    {
        if (width == 0 || height == 0 ||
            width > options.MaxImageDimension ||
            height > options.MaxImageDimension)
        {
            throw new MediaSanitizationException("Image dimensions exceed the safe limit.");
        }
        var pixels = checked((ulong)width * height);
        var bytes = checked(pixels * 4UL);
        if (pixels > (ulong)options.MaxImagePixels ||
            bytes > (ulong)options.MaxDecodedImageBytes)
        {
            throw new MediaSanitizationException("Image pixels exceed the safe decoded-memory budget.");
        }
    }

    private static void ResizeStillImageIfNeeded(MagickImage image, int maxLongEdge)
    {
        var currentLongEdge = Math.Max(image.Width, image.Height);
        if (currentLongEdge <= maxLongEdge)
        {
            return;
        }
        uint width;
        uint height;
        if (image.Width >= image.Height)
        {
            width = (uint)maxLongEdge;
            height = Math.Max(1u, (uint)Math.Round(
                image.Height * (double)maxLongEdge / image.Width,
                MidpointRounding.AwayFromZero));
        }
        else
        {
            height = (uint)maxLongEdge;
            width = Math.Max(1u, (uint)Math.Round(
                image.Width * (double)maxLongEdge / image.Height,
                MidpointRounding.AwayFromZero));
        }
        image.Resize(width, height, FilterType.Lanczos);
    }

    private static MagickFormat ResolveImageFormat(string contentType) =>
        contentType.ToLowerInvariant() switch
        {
            "image/jpeg" => MagickFormat.Jpeg,
            "image/png" => MagickFormat.Png,
            "image/gif" => MagickFormat.Gif,
            "image/webp" => MagickFormat.WebP,
            "image/avif" => MagickFormat.Avif,
            _ => throw new MediaSanitizationException("Image format is unsupported.")
        };

    private static StillOutput ResolveStillOutput(
        string inputContentType,
        bool hasTransparency,
        string preferred)
    {
        if (inputContentType.Equals("image/gif", StringComparison.OrdinalIgnoreCase))
        {
            return new StillOutput("image/gif", ".gif", MagickFormat.Gif);
        }
        var normalized = (preferred ?? "preserve").Trim().ToLowerInvariant();
        var output = normalized switch
        {
            "preserve" => inputContentType.ToLowerInvariant() switch
            {
                "image/jpeg" => new StillOutput("image/jpeg", ".jpg", MagickFormat.Jpeg),
                "image/png" => new StillOutput("image/png", ".png", MagickFormat.Png),
                "image/webp" => new StillOutput("image/webp", ".webp", MagickFormat.WebP),
                "image/avif" => new StillOutput("image/avif", ".avif", MagickFormat.Avif),
                _ => throw new MediaSanitizationException("Image output format is unsupported.")
            },
            "avif" => new StillOutput("image/avif", ".avif", MagickFormat.Avif),
            "webp" => new StillOutput("image/webp", ".webp", MagickFormat.WebP),
            "jpeg" or "jpg" => new StillOutput("image/jpeg", ".jpg", MagickFormat.Jpeg),
            _ => throw new MediaSanitizationException("Preferred still image format is invalid.")
        };

        // JPEG has no alpha channel. Falling back to WebP is preferable to silently
        // compositing transparent pixels against black or white.
        if (hasTransparency && output.Format == MagickFormat.Jpeg)
        {
            return new StillOutput("image/webp", ".webp", MagickFormat.WebP);
        }
        return output;
    }

    private static void VerifyStillOutput(
        string contentType,
        string path,
        uint expectedWidth,
        uint expectedHeight,
        UploadStorageOptions options,
        CancellationToken cancellationToken)
    {
        using var metadata = new MagickImageCollection();
        metadata.Ping(path, new MagickReadSettings { Format = ResolveImageFormat(contentType) });
        if (metadata.Count != 1 || metadata[0].Width != expectedWidth || metadata[0].Height != expectedHeight)
        {
            throw new MediaSanitizationException("Encoded image dimensions or frame count changed unexpectedly.");
        }
        ValidateImageGeometry(metadata[0].Width, metadata[0].Height, options);
        using var decoded = new MagickImage(path, ResolveImageFormat(contentType));
        if (decoded.ProfileNames.Any() || !string.IsNullOrEmpty(decoded.Comment))
        {
            throw new MediaSanitizationException("Encoded image still contains privacy metadata.");
        }
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static void VerifyAnimatedOutput(
        string contentType,
        string path,
        int expectedFrameCount,
        UploadStorageOptions options,
        CancellationToken cancellationToken)
    {
        using var decoded = new MagickImageCollection();
        decoded.Read(path, new MagickReadSettings { Format = ResolveImageFormat(contentType) });
        if (decoded.Count != expectedFrameCount)
        {
            throw new MediaSanitizationException("Encoded animation frame count changed unexpectedly.");
        }
        ValidateImageCollectionGeometry(decoded, options);
        foreach (var frame in decoded)
        {
            if (frame.ProfileNames.Any() || !string.IsNullOrEmpty(frame.Comment))
            {
                throw new MediaSanitizationException("Encoded animation still contains privacy metadata.");
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static async Task WriteNewFileAsync(
        string destinationPath,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        await using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
        await destination.WriteAsync(bytes, cancellationToken);
        await destination.FlushAsync(cancellationToken);
        destination.Flush(flushToDisk: true);
    }

    private static MediaSanitizationResult UnchangedImageResult(string contentType) =>
        contentType.ToLowerInvariant() switch
        {
            "image/jpeg" => new(contentType, ".jpg"),
            "image/png" => new(contentType, ".png"),
            "image/gif" => new(contentType, ".gif"),
            "image/webp" => new(contentType, ".webp"),
            "image/avif" => new(contentType, ".avif"),
            _ => new(contentType, null)
        };

    private sealed record StillOutput(
        string ContentType,
        string StorageExtension,
        MagickFormat Format);

    private static byte[] SanitizeJpeg(byte[] source)
    {
        if (source.Length < 4 || source[0] != 0xFF || source[1] != 0xD8)
        {
            throw new MediaSanitizationException("JPEG start marker is missing.");
        }

        using var output = new MemoryStream(source.Length);
        output.Write(source, 0, 2);
        var offset = 2;
        var inEntropyData = false;
        var sawFrame = false;
        var sawScan = false;
        var sawEnd = false;
        var wroteJfif = false;
        var wroteAdobeColorTransform = false;
        var wroteOrientation = false;

        while (offset < source.Length)
        {
            if (inEntropyData)
            {
                var entropyStart = offset;
                while (offset < source.Length && source[offset] != 0xFF)
                {
                    offset++;
                }
                output.Write(source, entropyStart, offset - entropyStart);
                if (offset >= source.Length)
                {
                    break;
                }

                var markerStart = offset;
                while (offset < source.Length && source[offset] == 0xFF)
                {
                    offset++;
                }
                if (offset >= source.Length)
                {
                    throw new MediaSanitizationException("JPEG entropy marker is truncated.");
                }

                var entropyMarker = source[offset];
                if (entropyMarker == 0x00 || entropyMarker is >= 0xD0 and <= 0xD7)
                {
                    output.Write(source, markerStart, offset - markerStart + 1);
                    offset++;
                    continue;
                }

                inEntropyData = false;
                offset = markerStart;
                continue;
            }

            if (source[offset] != 0xFF)
            {
                throw new MediaSanitizationException("JPEG marker boundary is invalid.");
            }

            while (offset < source.Length && source[offset] == 0xFF)
            {
                offset++;
            }
            if (offset >= source.Length)
            {
                throw new MediaSanitizationException("JPEG marker is truncated.");
            }

            var marker = source[offset++];
            if (marker == 0xD9)
            {
                output.WriteByte(0xFF);
                output.WriteByte(0xD9);
                sawEnd = true;
                break;
            }

            if (marker == 0xD8 || marker == 0x00 || marker is >= 0xD0 and <= 0xD7)
            {
                throw new MediaSanitizationException("JPEG contains an invalid standalone marker.");
            }

            if (marker == 0x01)
            {
                output.WriteByte(0xFF);
                output.WriteByte(marker);
                continue;
            }

            if (offset > source.Length - 2)
            {
                throw new MediaSanitizationException("JPEG segment length is truncated.");
            }
            var segmentLength = BinaryPrimitives.ReadUInt16BigEndian(source.AsSpan(offset, 2));
            if (segmentLength < 2 || offset > source.Length - segmentLength)
            {
                throw new MediaSanitizationException("JPEG segment length is invalid.");
            }

            var segmentEnd = offset + segmentLength;
            var payload = source.AsSpan(offset + 2, segmentLength - 2);
            var isMetadata = marker is >= 0xE0 and <= 0xEF || marker == 0xFE;
            if (marker == 0xE0 && !wroteJfif && TryBuildSafeJfif(payload, out var jfif))
            {
                WriteJpegSegment(output, marker, jfif);
                wroteJfif = true;
            }
            else if (marker == 0xEE &&
                     !wroteAdobeColorTransform &&
                     TryBuildSafeAdobeColorTransform(payload, out var adobe))
            {
                WriteJpegSegment(output, marker, adobe);
                wroteAdobeColorTransform = true;
            }
            else if (marker == 0xE1 &&
                     !wroteOrientation &&
                     TryReadExifOrientation(payload, out var orientation))
            {
                WriteJpegSegment(output, marker, BuildMinimalExifOrientation(orientation));
                wroteOrientation = true;
            }
            else if (!isMetadata)
            {
                output.WriteByte(0xFF);
                output.WriteByte(marker);
                output.Write(source, offset, segmentLength);
            }

            if (IsJpegStartOfFrame(marker))
            {
                sawFrame = true;
            }
            if (marker == 0xDA)
            {
                sawScan = true;
                inEntropyData = true;
            }
            offset = segmentEnd;
        }

        if (!sawFrame || !sawScan || !sawEnd)
        {
            throw new MediaSanitizationException("JPEG structure is incomplete.");
        }
        return output.ToArray();
    }

    private static bool IsJpegStartOfFrame(byte marker) =>
        marker is >= 0xC0 and <= 0xCF && marker is not (0xC4 or 0xC8 or 0xCC);

    private static bool TryBuildSafeJfif(ReadOnlySpan<byte> payload, out byte[] safePayload)
    {
        safePayload = [];
        if (payload.Length < 14 || !payload[..5].SequenceEqual("JFIF\0"u8))
        {
            return false;
        }

        safePayload = payload[..14].ToArray();
        // JFIF's optional thumbnail can expose an unredacted image. Density/version
        // fields are rendering metadata only, so retain them and force no thumbnail.
        safePayload[12] = 0;
        safePayload[13] = 0;
        return true;
    }

    private static bool TryBuildSafeAdobeColorTransform(
        ReadOnlySpan<byte> payload,
        out byte[] safePayload)
    {
        safePayload = [];
        if (payload.Length < 12 || !payload[..5].SequenceEqual("Adobe"u8))
        {
            return false;
        }

        // APP14's 12-byte Adobe record controls CMYK/YCCK interpretation. Retain
        // only that fixed rendering record and discard any appended bytes.
        safePayload = payload[..12].ToArray();
        return true;
    }

    private static bool TryReadExifOrientation(ReadOnlySpan<byte> payload, out ushort orientation)
    {
        orientation = 0;
        if (payload.Length < 14 || !payload[..6].SequenceEqual("Exif\0\0"u8))
        {
            return false;
        }

        var tiff = payload[6..];
        var littleEndian = tiff.Length >= 8 && tiff[0] == (byte)'I' && tiff[1] == (byte)'I';
        var bigEndian = tiff.Length >= 8 && tiff[0] == (byte)'M' && tiff[1] == (byte)'M';
        if (!littleEndian && !bigEndian)
        {
            return false;
        }

        ushort ReadUInt16(ReadOnlySpan<byte> value) => littleEndian
            ? BinaryPrimitives.ReadUInt16LittleEndian(value)
            : BinaryPrimitives.ReadUInt16BigEndian(value);
        uint ReadUInt32(ReadOnlySpan<byte> value) => littleEndian
            ? BinaryPrimitives.ReadUInt32LittleEndian(value)
            : BinaryPrimitives.ReadUInt32BigEndian(value);

        if (ReadUInt16(tiff.Slice(2, 2)) != 42)
        {
            return false;
        }
        var ifdOffsetValue = ReadUInt32(tiff.Slice(4, 4));
        if (ifdOffsetValue > int.MaxValue)
        {
            return false;
        }
        var ifdOffset = (int)ifdOffsetValue;
        if (ifdOffset < 8 || ifdOffset > tiff.Length - 2)
        {
            return false;
        }

        var entryCount = ReadUInt16(tiff.Slice(ifdOffset, 2));
        var entriesStart = ifdOffset + 2;
        if (entryCount > (tiff.Length - entriesStart) / 12)
        {
            return false;
        }
        for (var index = 0; index < entryCount; index++)
        {
            var entry = tiff.Slice(entriesStart + (index * 12), 12);
            if (ReadUInt16(entry[..2]) != 0x0112 ||
                ReadUInt16(entry.Slice(2, 2)) != 3 ||
                ReadUInt32(entry.Slice(4, 4)) != 1)
            {
                continue;
            }

            var candidate = ReadUInt16(entry.Slice(8, 2));
            if (candidate is >= 1 and <= 8)
            {
                orientation = candidate;
                return true;
            }
            return false;
        }
        return false;
    }

    private static byte[] BuildMinimalExifOrientation(ushort orientation)
    {
        var payload = new byte[32];
        "Exif\0\0"u8.CopyTo(payload);
        payload[6] = (byte)'I';
        payload[7] = (byte)'I';
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(8, 2), 42);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(10, 4), 8);
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(14, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(16, 2), 0x0112);
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(18, 2), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(20, 4), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(24, 2), orientation);
        // Bytes 26-27 are inline-value padding; bytes 28-31 are next-IFD offset 0.
        return payload;
    }

    private static void WriteJpegSegment(Stream output, byte marker, byte[] payload)
    {
        if (payload.Length > ushort.MaxValue - 2)
        {
            throw new MediaSanitizationException("JPEG rendering metadata is too large.");
        }
        output.WriteByte(0xFF);
        output.WriteByte(marker);
        Span<byte> length = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)(payload.Length + 2));
        output.Write(length);
        output.Write(payload);
    }

    private static byte[] SanitizePng(byte[] source)
    {
        ReadOnlySpan<byte> signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if (source.Length < signature.Length || !source.AsSpan(0, signature.Length).SequenceEqual(signature))
        {
            throw new MediaSanitizationException("PNG signature is missing.");
        }

        using var output = new MemoryStream(source.Length);
        output.Write(signature);
        var offset = signature.Length;
        var sawHeader = false;
        var sawImageData = false;
        var sawEnd = false;

        while (offset < source.Length)
        {
            if (source.Length - offset < 12)
            {
                throw new MediaSanitizationException("PNG chunk is truncated.");
            }
            var dataLength = BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(offset, 4));
            if (dataLength > int.MaxValue)
            {
                throw new MediaSanitizationException("PNG chunk is too large.");
            }
            var chunkLength = checked(12 + (int)dataLength);
            if (offset > source.Length - chunkLength)
            {
                throw new MediaSanitizationException("PNG chunk length is invalid.");
            }

            var typeBytes = source.AsSpan(offset + 4, 4);
            var type = Encoding.ASCII.GetString(typeBytes);
            var expectedCrc = BinaryPrimitives.ReadUInt32BigEndian(
                source.AsSpan(offset + 8 + (int)dataLength, 4));
            var actualCrc = ComputePngCrc(source.AsSpan(offset + 4, 4 + (int)dataLength));
            if (expectedCrc != actualCrc)
            {
                throw new MediaSanitizationException("PNG chunk checksum is invalid.");
            }

            if (!sawHeader && type != "IHDR")
            {
                throw new MediaSanitizationException("PNG IHDR must be the first chunk.");
            }
            if (type == "IHDR")
            {
                if (sawHeader || dataLength != 13)
                {
                    throw new MediaSanitizationException("PNG IHDR is invalid.");
                }
                sawHeader = true;
            }
            else if (type == "IDAT")
            {
                sawImageData = true;
            }
            else if (type == "IEND")
            {
                if (dataLength != 0)
                {
                    throw new MediaSanitizationException("PNG IEND is invalid.");
                }
                sawEnd = true;
            }

            var isAncillary = (typeBytes[0] & 0x20) != 0;
            var preserve = !isAncillary
                ? type is "IHDR" or "PLTE" or "IDAT" or "IEND"
                : PngPreservedAncillaryChunks.Contains(type);
            if (!isAncillary && !preserve)
            {
                throw new MediaSanitizationException("PNG contains an unknown critical chunk.");
            }
            if (preserve)
            {
                output.Write(source, offset, chunkLength);
            }

            offset += chunkLength;
            if (sawEnd)
            {
                if (offset != source.Length)
                {
                    throw new MediaSanitizationException("PNG contains data after IEND.");
                }
                break;
            }
        }

        if (!sawHeader || !sawImageData || !sawEnd)
        {
            throw new MediaSanitizationException("PNG structure is incomplete.");
        }
        return output.ToArray();
    }

    private static uint ComputePngCrc(ReadOnlySpan<byte> bytes)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in bytes)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }
        return ~crc;
    }

    private static byte[] SanitizeGif(byte[] source)
    {
        if (source.Length < 13 ||
            !(source.AsSpan(0, 6).SequenceEqual("GIF87a"u8) ||
              source.AsSpan(0, 6).SequenceEqual("GIF89a"u8)))
        {
            throw new MediaSanitizationException("GIF header is invalid.");
        }

        using var output = new MemoryStream(source.Length);
        output.Write(source, 0, 13);
        var offset = 13;
        var packed = source[10];
        if ((packed & 0x80) != 0)
        {
            var colorTableBytes = checked(3 * (1 << ((packed & 0x07) + 1)));
            CopyGifRange(source, output, ref offset, colorTableBytes);
        }

        var sawImage = false;
        var sawTrailer = false;
        while (offset < source.Length)
        {
            var introducer = source[offset];
            if (introducer == 0x3B)
            {
                output.WriteByte(0x3B);
                offset++;
                sawTrailer = true;
                break;
            }
            if (introducer == 0x2C)
            {
                var descriptorStart = offset;
                EnsureAvailable(source, offset, 10, "GIF image descriptor is truncated.");
                offset += 10;
                var imagePacked = source[descriptorStart + 9];
                if ((imagePacked & 0x80) != 0)
                {
                    var localTableBytes = checked(3 * (1 << ((imagePacked & 0x07) + 1)));
                    EnsureAvailable(source, offset, localTableBytes, "GIF local color table is truncated.");
                    offset += localTableBytes;
                }
                EnsureAvailable(source, offset, 1, "GIF image code size is truncated.");
                offset++;
                SkipGifSubBlocks(source, ref offset);
                output.Write(source, descriptorStart, offset - descriptorStart);
                sawImage = true;
                continue;
            }
            if (introducer != 0x21)
            {
                throw new MediaSanitizationException("GIF block introducer is invalid.");
            }

            EnsureAvailable(source, offset, 2, "GIF extension is truncated.");
            var extensionStart = offset;
            var label = source[offset + 1];
            offset += 2;
            if (label == 0xF9)
            {
                EnsureAvailable(source, offset, 6, "GIF graphic-control extension is truncated.");
                if (source[offset] != 4 || source[offset + 5] != 0)
                {
                    throw new MediaSanitizationException("GIF graphic-control extension is invalid.");
                }
                offset += 6;
                output.Write(source, extensionStart, offset - extensionStart);
                continue;
            }

            var keepApplicationLoop = false;
            if (label == 0xFF)
            {
                EnsureAvailable(source, offset, 1, "GIF application extension is truncated.");
                var appLength = source[offset];
                EnsureAvailable(source, offset + 1, appLength, "GIF application identifier is truncated.");
                if (appLength == 11)
                {
                    var identifier = Encoding.ASCII.GetString(source, offset + 1, 11);
                    keepApplicationLoop = identifier is "NETSCAPE2.0" or "ANIMEXTS1.0";
                }
            }

            SkipGifSubBlocks(source, ref offset);
            if (keepApplicationLoop)
            {
                output.Write(source, extensionStart, offset - extensionStart);
            }
        }

        if (!sawImage || !sawTrailer || offset != source.Length)
        {
            throw new MediaSanitizationException("GIF structure is incomplete.");
        }
        return output.ToArray();
    }

    private static void SkipGifSubBlocks(byte[] source, ref int offset)
    {
        while (true)
        {
            EnsureAvailable(source, offset, 1, "GIF data sub-block is truncated.");
            var length = source[offset++];
            if (length == 0)
            {
                return;
            }
            EnsureAvailable(source, offset, length, "GIF data sub-block payload is truncated.");
            offset += length;
        }
    }

    private static void CopyGifRange(byte[] source, Stream destination, ref int offset, int count)
    {
        EnsureAvailable(source, offset, count, "GIF color table is truncated.");
        destination.Write(source, offset, count);
        offset += count;
    }

    private static void EnsureAvailable(byte[] source, int offset, int count, string message)
    {
        if (offset < 0 || count < 0 || offset > source.Length - count)
        {
            throw new MediaSanitizationException(message);
        }
    }

    private static byte[] SanitizeWebp(byte[] source)
    {
        if (source.Length < 20 ||
            !source.AsSpan(0, 4).SequenceEqual("RIFF"u8) ||
            !source.AsSpan(8, 4).SequenceEqual("WEBP"u8))
        {
            throw new MediaSanitizationException("WebP RIFF header is invalid.");
        }
        var declaredSize = BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(4, 4));
        if (declaredSize != source.Length - 8)
        {
            throw new MediaSanitizationException("WebP RIFF length is invalid.");
        }

        using var output = new MemoryStream(source.Length);
        output.Write("RIFF"u8);
        output.Write(new byte[4]);
        output.Write("WEBP"u8);
        var offset = 12;
        var sawImagePayload = false;

        while (offset < source.Length)
        {
            EnsureAvailable(source, offset, 8, "WebP chunk header is truncated.");
            var type = Encoding.ASCII.GetString(source, offset, 4);
            var length = BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(offset + 4, 4));
            if (length > int.MaxValue)
            {
                throw new MediaSanitizationException("WebP chunk is too large.");
            }
            var paddedLength = checked((int)length + ((int)length & 1));
            EnsureAvailable(source, offset + 8, paddedLength, "WebP chunk payload is truncated.");

            if (WebpPayloadChunks.Contains(type))
            {
                output.Write(source, offset, 8);
                if (type == "VP8X")
                {
                    if (length != 10)
                    {
                        throw new MediaSanitizationException("WebP VP8X chunk is invalid.");
                    }
                    var payload = source.AsSpan(offset + 8, (int)length).ToArray();
                    payload[0] &= 0xD3; // clear ICC (0x20), EXIF (0x08), XMP (0x04)
                    output.Write(payload);
                    if ((length & 1) != 0)
                    {
                        output.WriteByte(0);
                    }
                }
                else
                {
                    output.Write(source, offset + 8, paddedLength);
                }

                if (type is "VP8 " or "VP8L" or "ANMF")
                {
                    sawImagePayload = true;
                }
            }
            offset += 8 + paddedLength;
        }

        if (!sawImagePayload)
        {
            throw new MediaSanitizationException("WebP image payload is missing.");
        }
        var result = output.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), checked((uint)(result.Length - 8)));
        return result;
    }

    private static async Task CopyFileAsync(
        string sourcePath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        await using var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await source.CopyToAsync(destination, cancellationToken);
        await destination.FlushAsync(cancellationToken);
    }

    private static async Task ScrubIsoBaseMediaAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough);
        var state = new IsoScrubState();
        await ScrubIsoBoxesAsync(stream, 0, stream.Length, 0, state, cancellationToken);
        if (!state.SawFileType || !state.SawMovie)
        {
            throw new MediaSanitizationException("MP4 container is missing required ftyp/moov boxes.");
        }
        await stream.FlushAsync(cancellationToken);
        stream.Flush(flushToDisk: true);
    }

    private static async Task ScrubIsoBoxesAsync(
        FileStream stream,
        long start,
        long end,
        int depth,
        IsoScrubState state,
        CancellationToken cancellationToken)
    {
        if (depth > MaxContainerDepth)
        {
            throw new MediaSanitizationException("MP4 metadata nesting is invalid.");
        }

        var offset = start;
        var header = new byte[16];
        while (offset < end)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (end - offset < 8)
            {
                throw new MediaSanitizationException("MP4 box header is truncated.");
            }

            stream.Position = offset;
            await ReadExactlyAsync(stream, header.AsMemory(0, 8), cancellationToken);
            var size32 = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            var type = Encoding.Latin1.GetString(header, 4, 4);
            var headerSize = 8L;
            long boxSize;
            if (size32 == 1)
            {
                await ReadExactlyAsync(stream, header.AsMemory(8, 8), cancellationToken);
                var size64 = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(8, 8));
                if (size64 > long.MaxValue)
                {
                    throw new MediaSanitizationException("MP4 extended box size is invalid.");
                }
                boxSize = (long)size64;
                headerSize = 16;
            }
            else if (size32 == 0)
            {
                boxSize = end - offset;
            }
            else
            {
                boxSize = size32;
            }

            if (boxSize < headerSize || offset > end - boxSize)
            {
                throw new MediaSanitizationException("MP4 box size is invalid.");
            }

            var payloadStart = offset + headerSize;
            var boxEnd = offset + boxSize;
            if (depth == 0 && type == "ftyp") state.SawFileType = true;
            if (depth == 0 && type == "moov") state.SawMovie = true;

            if (type == "trak" && await IsUnsafeIsoTrackAsync(
                    stream,
                    payloadStart,
                    boxEnd,
                    cancellationToken))
            {
                // Metadata track samples live in mdat, often outside the trak box. Merely
                // replacing trak would orphan but not erase GPS/camera bytes from the
                // downloadable file. Reject the whole upload instead of publishing that
                // residual data.
                throw new MediaSanitizationException(
                    "MP4 contains a metadata track that cannot be scrubbed safely.");
            }
            if (IsoMetadataBoxes.Contains(type))
            {
                await ReplaceWithZeroedFreeBoxAsync(
                    stream,
                    offset,
                    payloadStart,
                    boxEnd,
                    cancellationToken);
            }
            else
            {
                var isContainer = IsoContainerBoxes.Contains(type);
                if (!isContainer && !IsoAllowedLeafBoxes.Contains(type))
                {
                    throw new MediaSanitizationException(
                        $"MP4 contains an unsupported box '{type}'.");
                }
                if (type is "mvhd" or "tkhd" or "mdhd")
                {
                    await ZeroIsoCreationTimesAsync(stream, payloadStart, boxEnd, cancellationToken);
                }
                if (type == "hdlr")
                {
                    await ZeroIsoHandlerNameAsync(stream, payloadStart, boxEnd, cancellationToken);
                }
                if (isContainer)
                {
                    await ScrubIsoBoxesAsync(stream, payloadStart, boxEnd, depth + 1, state, cancellationToken);
                }
            }

            offset = boxEnd;
        }
    }

    private static async Task<bool> IsUnsafeIsoTrackAsync(
        FileStream stream,
        long trackStart,
        long trackEnd,
        CancellationToken cancellationToken)
    {
        var media = await FindIsoChildAsync(
            stream,
            trackStart,
            trackEnd,
            "mdia",
            cancellationToken);
        if (media is null)
        {
            throw new MediaSanitizationException("MP4 track is missing its media container.");
        }
        var handler = await FindIsoChildAsync(
            stream,
            media.Value.PayloadStart,
            media.Value.End,
            "hdlr",
            cancellationToken);
        if (handler is null || handler.Value.End - handler.Value.PayloadStart < 12)
        {
            throw new MediaSanitizationException("MP4 track handler is missing or truncated.");
        }

        var handlerTypeBytes = new byte[4];
        stream.Position = handler.Value.PayloadStart + 8;
        await ReadExactlyAsync(stream, handlerTypeBytes, cancellationToken);
        var handlerType = Encoding.Latin1.GetString(handlerTypeBytes);
        return handlerType is not ("vide" or "soun" or "subt" or "text" or "sbtl" or "clcp");
    }

    private static async Task<IsoBox?> FindIsoChildAsync(
        FileStream stream,
        long start,
        long end,
        string expectedType,
        CancellationToken cancellationToken)
    {
        var offset = start;
        var header = new byte[16];
        while (offset < end)
        {
            if (end - offset < 8)
            {
                throw new MediaSanitizationException("MP4 child box header is truncated.");
            }
            stream.Position = offset;
            await ReadExactlyAsync(stream, header.AsMemory(0, 8), cancellationToken);
            var size32 = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            var type = Encoding.Latin1.GetString(header, 4, 4);
            var headerSize = 8L;
            long size;
            if (size32 == 1)
            {
                await ReadExactlyAsync(stream, header.AsMemory(8, 8), cancellationToken);
                var size64 = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(8, 8));
                if (size64 > long.MaxValue)
                {
                    throw new MediaSanitizationException("MP4 child box size is invalid.");
                }
                size = (long)size64;
                headerSize = 16;
            }
            else if (size32 == 0)
            {
                size = end - offset;
            }
            else
            {
                size = size32;
            }
            if (size < headerSize || offset > end - size)
            {
                throw new MediaSanitizationException("MP4 child box exceeds its parent.");
            }

            var box = new IsoBox(offset + headerSize, offset + size);
            if (type == expectedType)
            {
                return box;
            }
            offset += size;
        }
        return null;
    }

    private static async Task ReplaceWithZeroedFreeBoxAsync(
        FileStream stream,
        long boxStart,
        long payloadStart,
        long boxEnd,
        CancellationToken cancellationToken)
    {
        stream.Position = boxStart + 4;
        await stream.WriteAsync("free"u8.ToArray(), cancellationToken);
        await ZeroRangeAsync(stream, payloadStart, boxEnd - payloadStart, cancellationToken);
    }

    private static async Task ZeroIsoCreationTimesAsync(
        FileStream stream,
        long payloadStart,
        long boxEnd,
        CancellationToken cancellationToken)
    {
        if (boxEnd - payloadStart < 12)
        {
            throw new MediaSanitizationException("MP4 full box is truncated.");
        }
        stream.Position = payloadStart;
        var version = stream.ReadByte();
        if (version is not (0 or 1))
        {
            throw new MediaSanitizationException("MP4 full box version is unsupported.");
        }
        var timestampBytes = version == 1 ? 16 : 8;
        if (boxEnd - payloadStart < 4 + timestampBytes)
        {
            throw new MediaSanitizationException("MP4 timestamp fields are truncated.");
        }
        await ZeroRangeAsync(stream, payloadStart + 4, timestampBytes, cancellationToken);
    }

    private static async Task ZeroIsoHandlerNameAsync(
        FileStream stream,
        long payloadStart,
        long boxEnd,
        CancellationToken cancellationToken)
    {
        // FullBox(4), pre_defined(4), handler_type(4), reserved(12), then an
        // optional human-readable handler name that often contains encoder/device data.
        const int fixedPayloadBytes = 24;
        if (boxEnd - payloadStart < fixedPayloadBytes)
        {
            throw new MediaSanitizationException("MP4 handler box is truncated.");
        }
        await ZeroRangeAsync(
            stream,
            payloadStart + fixedPayloadBytes,
            boxEnd - payloadStart - fixedPayloadBytes,
            cancellationToken);
    }

    private static async Task ScrubWebmAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough);

        var ebml = await ReadEbmlElementAsync(stream, 0, stream.Length, allowUnknownSize: false, cancellationToken);
        if (ebml.Id != 0x1A45DFA3)
        {
            throw new MediaSanitizationException("WebM EBML header is missing.");
        }
        if (!await EbmlHeaderDeclaresWebmAsync(stream, ebml, cancellationToken))
        {
            throw new MediaSanitizationException("EBML document is not WebM.");
        }

        var segment = await ReadEbmlElementAsync(
            stream,
            ebml.End,
            stream.Length,
            allowUnknownSize: true,
            cancellationToken);
        if (segment.Id != 0x18538067 || segment.End != stream.Length)
        {
            throw new MediaSanitizationException("WebM Segment is invalid.");
        }

        await ScrubWebmChildrenAsync(
            stream,
            segment.PayloadStart,
            segment.End,
            0,
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        stream.Flush(flushToDisk: true);
    }

    private static async Task<bool> EbmlHeaderDeclaresWebmAsync(
        FileStream stream,
        EbmlElement header,
        CancellationToken cancellationToken)
    {
        var offset = header.PayloadStart;
        var declaresWebm = false;
        while (offset < header.End)
        {
            var child = await ReadEbmlElementAsync(stream, offset, header.End, false, cancellationToken);
            if (!EbmlHeaderElements.Contains(child.Id))
            {
                return false;
            }
            if (child.Id == 0x4282)
            {
                if (child.Size is <= 0 or > 16)
                {
                    return false;
                }
                var value = new byte[(int)child.Size];
                stream.Position = child.PayloadStart;
                await ReadExactlyAsync(stream, value, cancellationToken);
                declaresWebm = Encoding.ASCII.GetString(value)
                    .Equals("webm", StringComparison.OrdinalIgnoreCase);
            }
            offset = child.End;
        }
        return declaresWebm;
    }

    private static async Task ScrubWebmChildrenAsync(
        FileStream stream,
        long start,
        long end,
        int depth,
        CancellationToken cancellationToken)
    {
        if (depth > MaxContainerDepth)
        {
            throw new MediaSanitizationException("WebM metadata nesting is invalid.");
        }

        var offset = start;
        while (offset < end)
        {
            var element = await ReadEbmlElementAsync(stream, offset, end, false, cancellationToken);
            if (depth == 0 && !EbmlSegmentElements.Contains(element.Id))
            {
                throw new MediaSanitizationException("WebM Segment contains an unknown element.");
            }
            if (EbmlSensitiveMasterElements.Contains(element.Id) || EbmlSensitiveElements.Contains(element.Id))
            {
                await ReplaceEbmlElementWithVoidAsync(stream, element, cancellationToken);
            }
            else if (EbmlTraversedMasterElements.Contains(element.Id))
            {
                await ScrubWebmChildrenAsync(
                    stream,
                    element.PayloadStart,
                    element.End,
                    depth + 1,
                    cancellationToken);
            }
            else if (depth > 0 && !EbmlAllowedNestedLeafElements.Contains(element.Id))
            {
                throw new MediaSanitizationException(
                    $"WebM contains an unsupported nested element 0x{element.Id:X}.");
            }
            offset = element.End;
        }
    }

    private static async Task<EbmlElement> ReadEbmlElementAsync(
        FileStream stream,
        long offset,
        long containingEnd,
        bool allowUnknownSize,
        CancellationToken cancellationToken)
    {
        if (offset >= containingEnd)
        {
            throw new MediaSanitizationException("EBML element is missing.");
        }
        stream.Position = offset;
        var firstId = stream.ReadByte();
        if (firstId <= 0)
        {
            throw new MediaSanitizationException("EBML element ID is invalid.");
        }
        var idLength = GetEbmlVintLength((byte)firstId, 4);
        var idBytes = new byte[idLength];
        idBytes[0] = (byte)firstId;
        if (idLength > 1)
        {
            await ReadExactlyAsync(stream, idBytes.AsMemory(1), cancellationToken);
        }
        ulong id = 0;
        foreach (var value in idBytes)
        {
            id = (id << 8) | value;
        }

        var firstSize = stream.ReadByte();
        if (firstSize < 0)
        {
            throw new MediaSanitizationException("EBML element size is truncated.");
        }
        var sizeLength = GetEbmlVintLength((byte)firstSize, 8);
        ulong size = (byte)firstSize & (ulong)(0xFF >> sizeLength);
        for (var index = 1; index < sizeLength; index++)
        {
            var next = stream.ReadByte();
            if (next < 0)
            {
                throw new MediaSanitizationException("EBML element size is truncated.");
            }
            size = (size << 8) | (byte)next;
        }
        var unknownValue = sizeLength == 8
            ? 0x00FFFFFFFFFFFFFFUL
            : (1UL << (7 * sizeLength)) - 1;
        var isUnknown = size == unknownValue;
        if (isUnknown && !allowUnknownSize)
        {
            throw new MediaSanitizationException("Unknown EBML element size is not safe here.");
        }

        var payloadStart = checked(offset + idLength + sizeLength);
        var end = isUnknown ? containingEnd : checked(payloadStart + (long)size);
        if (end < payloadStart || end > containingEnd)
        {
            throw new MediaSanitizationException("EBML element exceeds its container.");
        }
        return new EbmlElement(id, offset, payloadStart, end, idLength, sizeLength, end - payloadStart);
    }

    private static int GetEbmlVintLength(byte first, int maxLength)
    {
        for (var length = 1; length <= maxLength; length++)
        {
            if ((first & (0x80 >> (length - 1))) != 0)
            {
                return length;
            }
        }
        throw new MediaSanitizationException("EBML variable-length integer is invalid.");
    }

    private static async Task ReplaceEbmlElementWithVoidAsync(
        FileStream stream,
        EbmlElement element,
        CancellationToken cancellationToken)
    {
        var totalLength = element.End - element.Start;
        var sizeLength = 0;
        long payloadLength = 0;
        for (var candidate = 1; candidate <= 8; candidate++)
        {
            payloadLength = totalLength - 1 - candidate;
            if (payloadLength < 0)
            {
                break;
            }
            var maxValue = candidate == 8
                ? 0x00FFFFFFFFFFFFFEUL
                : (1UL << (7 * candidate)) - 2;
            if ((ulong)payloadLength <= maxValue)
            {
                sizeLength = candidate;
                break;
            }
        }
        if (sizeLength == 0)
        {
            throw new MediaSanitizationException("EBML metadata element cannot be replaced safely.");
        }

        stream.Position = element.Start;
        stream.WriteByte(0xEC); // Void
        var encodedSize = EncodeEbmlSize((ulong)payloadLength, sizeLength);
        await stream.WriteAsync(encodedSize, cancellationToken);
        await ZeroRangeAsync(stream, stream.Position, payloadLength, cancellationToken);
    }

    private static byte[] EncodeEbmlSize(ulong value, int length)
    {
        var result = new byte[length];
        for (var index = length - 1; index >= 0; index--)
        {
            result[index] = (byte)value;
            value >>= 8;
        }
        result[0] |= (byte)(0x80 >> (length - 1));
        return result;
    }

    private static async Task ZeroRangeAsync(
        FileStream stream,
        long start,
        long length,
        CancellationToken cancellationToken)
    {
        stream.Position = start;
        var remaining = length;
        while (remaining > 0)
        {
            var count = (int)Math.Min(remaining, ZeroBuffer.Length);
            await stream.WriteAsync(ZeroBuffer.AsMemory(0, count), cancellationToken);
            remaining -= count;
        }
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], cancellationToken);
            if (read == 0)
            {
                throw new MediaSanitizationException("Media container ended unexpectedly.");
            }
            total += read;
        }
    }

    private sealed class IsoScrubState
    {
        public bool SawFileType { get; set; }
        public bool SawMovie { get; set; }
    }

    private readonly record struct IsoBox(long PayloadStart, long End);

    private sealed record EbmlElement(
        ulong Id,
        long Start,
        long PayloadStart,
        long End,
        int IdLength,
        int SizeLength,
        long Size);
}
