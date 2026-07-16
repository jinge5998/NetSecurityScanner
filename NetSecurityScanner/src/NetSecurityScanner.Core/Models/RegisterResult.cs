namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 注册结果（含失败原因）
    /// </summary>
    public class RegisterResult
    {
        public bool Success { get; init; }
        public RegisterError ErrorCode { get; init; } = RegisterError.Ok;
        public string Message { get; init; } = "";

        public static RegisterResult Ok() => new() { Success = true, ErrorCode = RegisterError.Ok, Message = "注册成功" };
        public static RegisterResult Failed(RegisterError code, string msg) => new() { Success = false, ErrorCode = code, Message = msg };
    }

    public enum RegisterError
    {
        Ok = 0,
        InvalidUsername = 1,
        InvalidPassword = 2,
        InvalidEmail = 3,
        InvalidPhone = 4,
        UsernameTaken = 5,
        EmailTaken = 6,
        PhoneTaken = 7,
        ReasonTooLong = 8
    }
}
