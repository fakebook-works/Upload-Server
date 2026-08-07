using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using ImageMagick;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class MediaMetadataSanitizerTests
{
    [Fact]
    public async Task StoreValidatedFile_strips_png_location_and_capture_time_before_publish()
    {
        var root = CreateTemporaryDirectory();
        try
        {
            var source = CreatePng(
                ("tEXt", Encoding.UTF8.GetBytes("Location\0Saigon")),
                ("eXIf", Encoding.UTF8.GetBytes("GPSLatitude=10.8231;DateTimeOriginal=2026:08:07 08:30:00")),
                ("tIME", [0x07, 0xEA, 0x08, 0x07, 0x08, 0x1E, 0x00]));
            await using var input = new MemoryStream(source);
            var file = new FormFile(input, 0, source.Length, "file", "camera.png")
            {
                Headers = new HeaderDictionary(),
                ContentType = "image/png"
            };
            var options = new UploadStorageOptions
            {
                RootPath = root,
                StagedUploadsEnabled = true,
                PendingLifetimeMinutes = 60
            };
            var store = new UploadAssetStore(Options.Create(options));

            var result = await UploadSecurity.StoreValidatedFileAsync(
                file,
                42,
                options,
                store,
                CancellationToken.None);

            Assert.True(result.IsAllowed, result.Error);
            var storedName = Path.GetFileName(result.Response!.Url);
            var published = await File.ReadAllBytesAsync(Path.Combine(root, storedName));
            Assert.DoesNotContain("tEXt", Encoding.Latin1.GetString(published), StringComparison.Ordinal);
            Assert.DoesNotContain("eXIf", Encoding.Latin1.GetString(published), StringComparison.Ordinal);
            Assert.DoesNotContain("tIME", Encoding.Latin1.GetString(published), StringComparison.Ordinal);
            Assert.DoesNotContain("Saigon", Encoding.Latin1.GetString(published), StringComparison.Ordinal);
            var lifecycle = JsonSerializer.Deserialize<UploadAssetMetadata>(
                await File.ReadAllTextAsync(Path.Combine(
                    root,
                    ".metadata",
                    result.Response.AssetId + ".json")),
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.Equal(UploadAssetStore.CurrentPrivacyMetadataVersion, lifecycle!.PrivacyMetadataVersion);
            Assert.NotNull(lifecycle.PrivacyMetadataSanitizedAt);
            Assert.Empty(Directory.EnumerateFiles(Path.Combine(root, ".quarantine")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StoreValidatedFile_fails_closed_without_publishing_a_malformed_image()
    {
        var root = CreateTemporaryDirectory();
        try
        {
            byte[] source = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];
            await using var input = new MemoryStream(source);
            var file = new FormFile(input, 0, source.Length, "file", "broken.png")
            {
                Headers = new HeaderDictionary(),
                ContentType = "image/png"
            };
            var options = new UploadStorageOptions { RootPath = root, StagedUploadsEnabled = true };
            var store = new UploadAssetStore(Options.Create(options));

            var result = await UploadSecurity.StoreValidatedFileAsync(
                file,
                42,
                options,
                store,
                CancellationToken.None);

            Assert.False(result.IsAllowed);
            Assert.Equal("Media metadata could not be removed safely.", result.Error);
            Assert.Empty(Directory.EnumerateFiles(root));
            Assert.Empty(Directory.EnumerateFiles(Path.Combine(root, ".quarantine")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StoreValidatedFile_accepts_avif_and_publishes_matching_type_and_extension()
    {
        var root = CreateTemporaryDirectory();
        try
        {
            var source = CreateValidImage(MagickFormat.Avif, 6, 4);
            await using var input = new MemoryStream(source);
            var file = new FormFile(input, 0, source.Length, "file", "camera.avif")
            {
                Headers = new HeaderDictionary(),
                ContentType = "image/avif"
            };
            var options = new UploadStorageOptions
            {
                RootPath = root,
                StagedUploadsEnabled = true,
                PendingLifetimeMinutes = 60,
                PreferredStillImageFormat = "preserve"
            };
            var store = new UploadAssetStore(Options.Create(options));

            var result = await UploadSecurity.StoreValidatedFileAsync(
                file,
                42,
                options,
                store,
                CancellationToken.None);

            Assert.True(result.IsAllowed, result.Error);
            Assert.Equal("image/avif", result.Response!.ContentType);
            Assert.EndsWith(".avif", result.Response.Url, StringComparison.Ordinal);
            using var decoded = new MagickImage(
                Path.Combine(root, Path.GetFileName(result.Response.Url)),
                MagickFormat.Avif);
            Assert.Equal((uint)6, decoded.Width);
            Assert.Equal((uint)4, decoded.Height);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Jpeg_keeps_only_safe_rendering_records_and_strips_exif_gps_and_comments()
    {
        var source = CreateJpegWithMetadata();
        var result = await SanitizeAsync("image/jpeg", source);
        var text = Encoding.Latin1.GetString(result);

        Assert.DoesNotContain("Exif", text, StringComparison.Ordinal);
        Assert.Contains("JFIF", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Adobe", text, StringComparison.Ordinal);
        Assert.DoesNotContain("GPSLatitude", text, StringComparison.Ordinal);
        Assert.DoesNotContain("DateTimeOriginal", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Photoshop", text, StringComparison.Ordinal);
        Assert.DoesNotContain("camera comment", text, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRET_THUMBNAIL", text, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE_ADOBE_SUFFIX", text, StringComparison.Ordinal);
        Assert.True(result.AsSpan().StartsWith(new byte[] { 0xFF, 0xD8 }));
        Assert.True(result.AsSpan().EndsWith(new byte[] { 0xFF, 0xD9 }));
        using var decoded = new MagickImage(result, MagickFormat.Jpeg);
        Assert.Equal((uint)2, decoded.Width);
        Assert.Equal((uint)3, decoded.Height);
    }

    [Fact]
    public async Task Gif_strips_comments_but_preserves_animation_loop_extension()
    {
        var source = CreateGifWithCommentAndLoop();
        var result = await SanitizeAsync("image/gif", source);
        var text = Encoding.Latin1.GetString(result);

        Assert.DoesNotContain("GPS=10.8231", text, StringComparison.Ordinal);
        Assert.Contains("NETSCAPE2.0", text, StringComparison.Ordinal);
        Assert.Equal(0x3B, result[^1]);
        using var decoded = new MagickImageCollection(result, MagickFormat.Gif);
        Assert.Equal(2, decoded.Count);
    }

    [Fact]
    public async Task Webp_strips_exif_xmp_icc_and_clears_metadata_feature_flags()
    {
        var source = CreateWebpWithMetadata();
        var result = await SanitizeAsync("image/webp", source);
        var text = Encoding.Latin1.GetString(result);

        Assert.DoesNotContain("EXIF", text, StringComparison.Ordinal);
        Assert.DoesNotContain("XMP ", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ICCP", text, StringComparison.Ordinal);
        Assert.DoesNotContain("GPSLatitude", text, StringComparison.Ordinal);
        Assert.True(text.Contains("VP8 ", StringComparison.Ordinal) ||
                    text.Contains("VP8L", StringComparison.Ordinal));
        using var decoded = new MagickImage(result, MagickFormat.WebP);
        Assert.Equal((uint)2, decoded.Width);
        Assert.Equal((uint)2, decoded.Height);
    }

    [Fact]
    public async Task Animated_webp_is_scrubbed_without_flattening_frames()
    {
        var source = CreateAnimatedImage(MagickFormat.WebP);
        var result = await SanitizeAsync("image/webp", source);

        using var decoded = new MagickImageCollection(result, MagickFormat.WebP);
        Assert.Equal(2, decoded.Count);
        Assert.All(decoded, frame => Assert.Equal((uint)10, frame.AnimationDelay));
    }

    [Fact]
    public async Task Animated_avif_is_scrubbed_without_flattening_frames()
    {
        var source = CreateAnimatedImage(MagickFormat.Avif);
        var result = await SanitizeAsync("image/avif", source);

        using var decoded = new MagickImageCollection(result, MagickFormat.Avif);
        Assert.Equal(2, decoded.Count);
    }

    [Fact]
    public async Task Still_image_can_be_lossily_converted_to_avif_without_metadata()
    {
        var source = CreateJpegWithMetadata();
        var options = new UploadStorageOptions
        {
            PreferredStillImageFormat = "avif",
            ImageLossyQuality = 78
        };

        var (sanitization, result) = await SanitizeWithOptionsAsync(
            "image/jpeg",
            source,
            options);

        Assert.Equal("image/avif", sanitization.ContentType);
        Assert.Equal(".avif", sanitization.StorageExtension);
        Assert.True(result.Length >= 16);
        Assert.Equal("ftyp", Encoding.ASCII.GetString(result, 4, 4));
        using var decoded = new MagickImage(result, MagickFormat.Avif);
        Assert.Equal((uint)2, decoded.Width);
        Assert.Equal((uint)3, decoded.Height);
        Assert.Empty(decoded.ProfileNames);
        Assert.True(string.IsNullOrEmpty(decoded.Comment));
    }

    [Fact]
    public async Task Transparent_image_falls_back_to_webp_when_jpeg_is_preferred()
    {
        var source = CreateTransparentImage(MagickFormat.Png, 4, 3);
        var options = new UploadStorageOptions
        {
            PreferredStillImageFormat = "jpeg",
            ImageLossyQuality = 78
        };

        var (sanitization, result) = await SanitizeWithOptionsAsync(
            "image/png",
            source,
            options);

        Assert.Equal("image/webp", sanitization.ContentType);
        Assert.Equal(".webp", sanitization.StorageExtension);
        using var decoded = new MagickImage(result, MagickFormat.WebP);
        Assert.True(decoded.HasAlpha);
        Assert.Equal((uint)4, decoded.Width);
        Assert.Equal((uint)3, decoded.Height);
    }

    [Fact]
    public async Task Image_pixel_budget_rejects_before_publication()
    {
        var root = CreateTemporaryDirectory();
        try
        {
            var sourcePath = Path.Combine(root, "source.png");
            var destinationPath = Path.Combine(root, "destination.png");
            await File.WriteAllBytesAsync(sourcePath, CreateValidImage(MagickFormat.Png, 100, 100));
            var options = new UploadStorageOptions
            {
                MaxImagePixels = 9_999,
                MaxDecodedImageBytes = 16 * 1024 * 1024
            };

            await Assert.ThrowsAsync<MediaSanitizationException>(() =>
                MediaMetadataSanitizer.SanitizeAsync(
                    "image/png",
                    sourcePath,
                    destinationPath,
                    options,
                    CancellationToken.None));
            Assert.False(File.Exists(destinationPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Stored_dimension_cap_downscales_with_aspect_ratio_preserved()
    {
        var source = CreateValidImage(MagickFormat.Jpeg, 10, 5);
        var options = new UploadStorageOptions
        {
            MaxStoredImageDimension = 4,
            PreferredStillImageFormat = "preserve",
            ImageLossyQuality = 78
        };

        var (_, result) = await SanitizeWithOptionsAsync("image/jpeg", source, options);

        using var decoded = new MagickImage(result, MagickFormat.Jpeg);
        Assert.Equal((uint)4, decoded.Width);
        Assert.Equal((uint)2, decoded.Height);
    }

    [Fact]
    public async Task Mp4_strips_location_user_data_and_zeroes_structural_capture_times()
    {
        var source = CreateMp4WithMetadata();
        var result = await SanitizeAsync("video/mp4", source);
        var text = Encoding.Latin1.GetString(result);

        Assert.DoesNotContain("+10.8231+106.6297/", text, StringComparison.Ordinal);
        Assert.DoesNotContain("DateTimeOriginal", text, StringComparison.Ordinal);
        Assert.Contains("free", text, StringComparison.Ordinal);
        var mvhd = FindAscii(result, "mvhd");
        Assert.True(mvhd >= 0);
        Assert.Equal(new byte[8], result.AsSpan(mvhd + 8, 8).ToArray());
    }

    [Fact]
    public async Task Mp4_with_timed_metadata_track_fails_closed_instead_of_orphaning_gps_samples()
    {
        var root = CreateTemporaryDirectory();
        try
        {
            var source = Path.Combine(root, "source.mp4");
            var destination = Path.Combine(root, "destination.mp4");
            await File.WriteAllBytesAsync(source, CreateMp4WithMetadataTrack());

            await Assert.ThrowsAsync<MediaSanitizationException>(() =>
                MediaMetadataSanitizer.SanitizeAsync(
                    "video/mp4",
                    source,
                    destination,
                    CancellationToken.None));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Mp4_zeroes_free_and_skip_padding_payloads()
    {
        using var source = new MemoryStream();
        WriteIsoBox(source, "ftyp", Encoding.ASCII.GetBytes("isom\0\0\x02\0isom"));
        WriteIsoBox(source, "free", Encoding.ASCII.GetBytes("GPSLatitude=10.8231"));
        WriteIsoBox(source, "skip", Encoding.ASCII.GetBytes("CameraSerial=SECRET"));
        WriteIsoBox(source, "moov", []);
        WriteIsoBox(source, "mdat", [1, 2, 3, 4]);

        var result = await SanitizeAsync("video/mp4", source.ToArray());
        var text = Encoding.Latin1.GetString(result);

        Assert.DoesNotContain("GPSLatitude", text, StringComparison.Ordinal);
        Assert.DoesNotContain("CameraSerial", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Mp4_unknown_vendor_box_fails_closed()
    {
        using var movie = new MemoryStream();
        WriteIsoBox(movie, "vndr", Encoding.ASCII.GetBytes("private vendor metadata"));
        using var source = new MemoryStream();
        WriteIsoBox(source, "ftyp", Encoding.ASCII.GetBytes("isom\0\0\x02\0isom"));
        WriteIsoBox(source, "moov", movie.ToArray());
        WriteIsoBox(source, "mdat", [1, 2, 3, 4]);

        await Assert.ThrowsAsync<MediaSanitizationException>(() =>
            SanitizeAsync("video/mp4", source.ToArray()));
    }

    [Fact]
    public async Task Webm_strips_date_title_application_tags_and_attachments()
    {
        var source = CreateWebmWithMetadata();
        var result = await SanitizeAsync("audio/webm", source);
        var text = Encoding.Latin1.GetString(result);

        Assert.DoesNotContain("Fakebook voice from Saigon", text, StringComparison.Ordinal);
        Assert.DoesNotContain("PrivateCameraApp", text, StringComparison.Ordinal);
        Assert.DoesNotContain("GPSLatitude", text, StringComparison.Ordinal);
        Assert.DoesNotContain("secret.jpg", text, StringComparison.Ordinal);
        Assert.Contains("webm", text, StringComparison.Ordinal);
        Assert.Contains((byte)0xEC, result);
    }

    [Fact]
    public async Task Webm_zeroes_void_payloads()
    {
        var ebml = CreateEbmlElement(
            0x1A45DFA3,
            CreateEbmlElement(0x4282, Encoding.ASCII.GetBytes("webm")));
        var segment = CreateEbmlElement(
            0x18538067,
            CreateEbmlElement(0xEC, Encoding.ASCII.GetBytes("GPSLatitude=10.8231")));

        var result = await SanitizeAsync("audio/webm", [.. ebml, .. segment]);

        Assert.DoesNotContain(
            "GPSLatitude",
            Encoding.Latin1.GetString(result),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Webm_unknown_nested_element_fails_closed()
    {
        var ebml = CreateEbmlElement(
            0x1A45DFA3,
            CreateEbmlElement(0x4282, Encoding.ASCII.GetBytes("webm")));
        var info = CreateEbmlElement(
            0x1549A966,
            CreateEbmlElement(0x4FFF, Encoding.ASCII.GetBytes("vendor metadata")));
        var segment = CreateEbmlElement(0x18538067, info);

        await Assert.ThrowsAsync<MediaSanitizationException>(() =>
            SanitizeAsync("audio/webm", [.. ebml, .. segment]));
    }

    [Fact]
    public async Task Unknown_media_container_fails_closed()
    {
        var root = CreateTemporaryDirectory();
        try
        {
            var source = Path.Combine(root, "source.bin");
            var destination = Path.Combine(root, "destination.bin");
            await File.WriteAllBytesAsync(source, [1, 2, 3]);

            await Assert.ThrowsAsync<MediaSanitizationException>(() =>
                MediaMetadataSanitizer.SanitizeAsync(
                    "video/quicktime",
                    source,
                    destination,
                    CancellationToken.None));
            Assert.False(File.Exists(destination));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    internal static byte[] CreatePng(params (string Type, byte[] Data)[] metadataChunks)
    {
        using var output = new MemoryStream();
        output.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        var ihdr = new byte[13];
        BinaryPrimitives.WriteUInt32BigEndian(ihdr.AsSpan(0, 4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(ihdr.AsSpan(4, 4), 1);
        ihdr[8] = 8;
        ihdr[9] = 6;
        WritePngChunk(output, "IHDR", ihdr);
        foreach (var chunk in metadataChunks)
        {
            WritePngChunk(output, chunk.Type, chunk.Data);
        }

        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            zlib.Write([0, 0x33, 0x66, 0x99, 0xFF]);
        }
        WritePngChunk(output, "IDAT", compressed.ToArray());
        WritePngChunk(output, "IEND", []);
        return output.ToArray();
    }

    internal static byte[] CreateMinimalMp4(int totalSize)
    {
        if (totalSize < 40)
        {
            throw new ArgumentOutOfRangeException(nameof(totalSize));
        }
        using var output = new MemoryStream(totalSize);
        WriteIsoBox(output, "ftyp", Encoding.ASCII.GetBytes("isom\0\0\x02\0isom"));
        var mdatSize = totalSize - checked((int)output.Length) - 8 - 8;
        WriteIsoBox(output, "mdat", new byte[mdatSize]);
        WriteIsoBox(output, "moov", []);
        return output.ToArray();
    }

    internal static byte[] CreateMinimalWebm()
    {
        var ebmlPayload = CreateEbmlElement(0x4282, Encoding.ASCII.GetBytes("webm"));
        var ebml = CreateEbmlElement(0x1A45DFA3, ebmlPayload);
        var segment = CreateEbmlElement(0x18538067, []);
        return [.. ebml, .. segment];
    }

    private static async Task<byte[]> SanitizeAsync(string contentType, byte[] source)
    {
        var root = CreateTemporaryDirectory();
        try
        {
            var sourcePath = Path.Combine(root, "source");
            var destinationPath = Path.Combine(root, "destination");
            await File.WriteAllBytesAsync(sourcePath, source);
            await MediaMetadataSanitizer.SanitizeAsync(
                contentType,
                sourcePath,
                destinationPath,
                CancellationToken.None);
            return await File.ReadAllBytesAsync(destinationPath);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<(MediaSanitizationResult Result, byte[] Bytes)> SanitizeWithOptionsAsync(
        string contentType,
        byte[] source,
        UploadStorageOptions options)
    {
        var root = CreateTemporaryDirectory();
        try
        {
            var sourcePath = Path.Combine(root, "source");
            var destinationPath = Path.Combine(root, "destination");
            await File.WriteAllBytesAsync(sourcePath, source);
            var result = await MediaMetadataSanitizer.SanitizeAsync(
                contentType,
                sourcePath,
                destinationPath,
                options,
                CancellationToken.None);
            return (result, await File.ReadAllBytesAsync(destinationPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] CreateJpegWithMetadata()
    {
        var validJpeg = CreateValidImage(MagickFormat.Jpeg, 3, 2);
        using var output = new MemoryStream();
        output.Write([0xFF, 0xD8]);
        WriteJpegSegment(
            output,
            0xE0,
            [
                .. "JFIF\0"u8.ToArray(),
                1, 2, 1, 0, 72, 0, 72, 1, 1,
                .. Encoding.ASCII.GetBytes("SECRET_THUMBNAIL")
            ]);
        WriteJpegSegment(output, 0xE1, CreateExifWithOrientationAndPrivateMetadata(6));
        WriteJpegSegment(output, 0xED, Encoding.ASCII.GetBytes("Photoshop 3.0\0IPTC location"));
        WriteJpegSegment(
            output,
            0xEE,
            [
                .. Encoding.ASCII.GetBytes("Adobe"),
                0, 100, 0, 0, 0, 0, 2,
                .. Encoding.ASCII.GetBytes("PRIVATE_ADOBE_SUFFIX")
            ]);
        WriteJpegSegment(output, 0xFE, Encoding.ASCII.GetBytes("camera comment"));
        output.Write(validJpeg.AsSpan(2));
        return output.ToArray();
    }

    private static byte[] CreateValidImage(MagickFormat format, uint width, uint height)
    {
        using var image = new MagickImage(MagickColors.CornflowerBlue, width, height);
        image.Format = format;
        image.Quality = 92;
        return image.ToByteArray(format);
    }

    private static byte[] CreateTransparentImage(MagickFormat format, uint width, uint height)
    {
        using var image = new MagickImage(MagickColors.Transparent, width, height);
        image.Format = format;
        image.Quality = 92;
        return image.ToByteArray(format);
    }

    private static byte[] CreateAnimatedImage(MagickFormat format)
    {
        using var images = new MagickImageCollection();
        images.Add(new MagickImage(MagickColors.Red, 3, 2));
        images.Add(new MagickImage(MagickColors.Blue, 3, 2));
        foreach (var image in images)
        {
            image.Format = format;
            image.AnimationDelay = 10;
            image.AnimationIterations = 0;
        }
        return images.ToByteArray(format);
    }

    private static byte[] CreateExifWithOrientationAndPrivateMetadata(ushort orientation)
    {
        var payload = new byte[96];
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
        Encoding.ASCII.GetBytes("GPSLatitude=10.8231;DateTimeOriginal=2026:08:07")
            .CopyTo(payload, 32);
        return payload;
    }

    private static void WriteJpegSegment(Stream output, byte marker, byte[] data)
    {
        output.WriteByte(0xFF);
        output.WriteByte(marker);
        Span<byte> length = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)(data.Length + 2)));
        output.Write(length);
        output.Write(data);
    }

    private static byte[] CreateGifWithCommentAndLoop()
    {
        using var images = new MagickImageCollection();
        images.Add(new MagickImage(MagickColors.Red, 2, 2));
        images.Add(new MagickImage(MagickColors.Blue, 2, 2));
        foreach (var image in images)
        {
            image.Format = MagickFormat.Gif;
            image.AnimationDelay = 10;
            image.AnimationIterations = 0;
        }
        images[0].Comment = "GPS=10.8231";
        return images.ToByteArray(MagickFormat.Gif);
    }

    private static byte[] CreateWebpWithMetadata()
    {
        var validWebp = CreateValidImage(MagickFormat.WebP, 2, 2);
        using var output = new MemoryStream();
        output.Write("RIFF"u8);
        output.Write(new byte[4]);
        output.Write("WEBP"u8);
        WriteRiffChunk(output, "VP8X", [0x2C, 0, 0, 0, 1, 0, 0, 1, 0, 0]);
        WriteRiffChunk(output, "EXIF", Encoding.ASCII.GetBytes("GPSLatitude=10.8231"));
        WriteRiffChunk(output, "XMP ", Encoding.ASCII.GetBytes("DateTimeOriginal=2026-08-07"));
        WriteRiffChunk(output, "ICCP", Encoding.ASCII.GetBytes("Camera profile"));
        output.Write(validWebp.AsSpan(12));
        var result = output.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), checked((uint)(result.Length - 8)));
        return result;
    }

    private static byte[] CreateMp4WithMetadata()
    {
        using var moviePayload = new MemoryStream();
        var movieHeader = new byte[20];
        movieHeader[0] = 0;
        movieHeader.AsSpan(4, 8).Fill(0x7F);
        WriteIsoBox(moviePayload, "mvhd", movieHeader);
        WriteIsoBox(moviePayload, "udta", Encoding.Latin1.GetBytes("©xyz+10.8231+106.6297/\0DateTimeOriginal"));

        using var output = new MemoryStream();
        WriteIsoBox(output, "ftyp", Encoding.ASCII.GetBytes("isom\0\0\x02\0isom"));
        WriteIsoBox(output, "moov", moviePayload.ToArray());
        WriteIsoBox(output, "mdat", [1, 2, 3, 4]);
        return output.ToArray();
    }

    private static byte[] CreateMp4WithMetadataTrack()
    {
        var handlerPayload = new byte[12];
        Encoding.ASCII.GetBytes("meta", handlerPayload.AsSpan(8, 4));
        using var mediaPayload = new MemoryStream();
        WriteIsoBox(mediaPayload, "hdlr", handlerPayload);
        using var trackPayload = new MemoryStream();
        WriteIsoBox(trackPayload, "mdia", mediaPayload.ToArray());
        using var moviePayload = new MemoryStream();
        WriteIsoBox(moviePayload, "trak", trackPayload.ToArray());

        using var output = new MemoryStream();
        WriteIsoBox(output, "ftyp", Encoding.ASCII.GetBytes("isom\0\0\x02\0isom"));
        WriteIsoBox(output, "moov", moviePayload.ToArray());
        WriteIsoBox(output, "mdat", Encoding.ASCII.GetBytes("GPSLatitude=10.8231"));
        return output.ToArray();
    }

    private static byte[] CreateWebmWithMetadata()
    {
        var ebml = CreateEbmlElement(
            0x1A45DFA3,
            CreateEbmlElement(0x4282, Encoding.ASCII.GetBytes("webm")));
        var info = CreateEbmlElement(
            0x1549A966,
            [
                .. CreateEbmlElement(0x4461, [1, 2, 3, 4, 5, 6, 7, 8]),
                .. CreateEbmlElement(0x7BA9, Encoding.UTF8.GetBytes("Fakebook voice from Saigon")),
                .. CreateEbmlElement(0x4D80, Encoding.UTF8.GetBytes("PrivateCameraApp"))
            ]);
        var tags = CreateEbmlElement(0x1254C367, Encoding.UTF8.GetBytes("GPSLatitude=10.8231"));
        var attachments = CreateEbmlElement(0x1941A469, Encoding.UTF8.GetBytes("secret.jpg"));
        var segment = CreateEbmlElement(0x18538067, [.. info, .. tags, .. attachments]);
        return [.. ebml, .. segment];
    }

    private static byte[] CreateEbmlElement(ulong id, byte[] payload)
    {
        var idBytes = EncodeEbmlId(id);
        var sizeBytes = EncodeEbmlSize((ulong)payload.Length);
        return [.. idBytes, .. sizeBytes, .. payload];
    }

    private static byte[] EncodeEbmlId(ulong id)
    {
        var length = id <= byte.MaxValue ? 1 : id <= ushort.MaxValue ? 2 : id <= 0xFFFFFF ? 3 : 4;
        var result = new byte[length];
        for (var index = length - 1; index >= 0; index--)
        {
            result[index] = (byte)id;
            id >>= 8;
        }
        return result;
    }

    private static byte[] EncodeEbmlSize(ulong value)
    {
        for (var length = 1; length <= 8; length++)
        {
            var max = length == 8 ? 0x00FFFFFFFFFFFFFEUL : (1UL << (7 * length)) - 2;
            if (value > max)
            {
                continue;
            }
            var result = new byte[length];
            var remaining = value;
            for (var index = length - 1; index >= 0; index--)
            {
                result[index] = (byte)remaining;
                remaining >>= 8;
            }
            result[0] |= (byte)(0x80 >> (length - 1));
            return result;
        }
        throw new InvalidOperationException("EBML payload is too large for this fixture.");
    }

    private static void WriteIsoBox(Stream output, string type, byte[] payload)
    {
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(header, checked((uint)(payload.Length + 8)));
        Encoding.Latin1.GetBytes(type, header[4..]);
        output.Write(header);
        output.Write(payload);
    }

    private static void WriteRiffChunk(Stream output, string type, byte[] payload)
    {
        output.Write(Encoding.ASCII.GetBytes(type));
        Span<byte> size = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(size, checked((uint)payload.Length));
        output.Write(size);
        output.Write(payload);
        if ((payload.Length & 1) != 0)
        {
            output.WriteByte(0);
        }
    }

    private static void WritePngChunk(Stream output, string type, byte[] data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)data.Length));
        output.Write(length);
        var typeBytes = Encoding.ASCII.GetBytes(type);
        output.Write(typeBytes);
        output.Write(data);
        Span<byte> crc = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(crc, ComputeCrc([.. typeBytes, .. data]));
        output.Write(crc);
    }

    private static uint ComputeCrc(ReadOnlySpan<byte> bytes)
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

    private static int FindAscii(byte[] bytes, string text) =>
        Encoding.Latin1.GetString(bytes).IndexOf(text, StringComparison.Ordinal);

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"fakebook-media-sanitize-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
