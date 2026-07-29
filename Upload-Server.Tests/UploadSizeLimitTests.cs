using Xunit;

public sealed class UploadSizeLimitTests
{
    private const long MiB = 1024L * 1024L;

    [Fact]
    public void Video_accepts_exactly_500_mib_and_rejects_one_byte_more()
    {
        Assert.Equal(500 * MiB, UploadSecurity.MaxVideoUploadBytes);

        var atLimit = UploadSecurity.ValidateMetadata(
            "reel.mp4",
            "video/mp4",
            UploadSecurity.MaxVideoUploadBytes);
        var overLimit = UploadSecurity.ValidateMetadata(
            "reel.mp4",
            "video/mp4",
            UploadSecurity.MaxVideoUploadBytes + 1);

        Assert.True(atLimit.IsAllowed);
        Assert.False(overLimit.IsAllowed);
    }

    [Fact]
    public void Raising_video_limit_does_not_raise_image_or_document_limit()
    {
        Assert.Equal(25 * MiB, UploadSecurity.MaxStandardUploadBytes);

        var imageAtLimit = UploadSecurity.ValidateMetadata(
            "photo.jpg",
            "image/jpeg",
            UploadSecurity.MaxStandardUploadBytes);
        var imageOverLimit = UploadSecurity.ValidateMetadata(
            "photo.jpg",
            "image/jpeg",
            UploadSecurity.MaxStandardUploadBytes + 1);
        var documentOverLimit = UploadSecurity.ValidateMetadata(
            "report.pdf",
            "application/pdf",
            UploadSecurity.MaxStandardUploadBytes + 1);

        Assert.True(imageAtLimit.IsAllowed);
        Assert.False(imageOverLimit.IsAllowed);
        Assert.False(documentOverLimit.IsAllowed);
    }

    [Fact]
    public void Multipart_request_limit_reserves_two_mib_for_form_overhead()
    {
        Assert.Equal(502 * MiB, UploadSecurity.MaxRequestBodyBytes);
        Assert.True(UploadSecurity.MaxRequestBodyBytes > UploadSecurity.MaxVideoUploadBytes);
    }
}
