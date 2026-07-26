namespace Foreman.Core.Security;

public static class PaymentCardDetection
{
    public static bool PassesLuhn(string? value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        var digits = value.Where(char.IsAsciiDigit).ToArray();
        if (digits.Length is < 12 or > 19) return false;

        var sum = 0;
        var alternate = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var n = digits[i] - '0';
            if (alternate && (n *= 2) > 9) n -= 9;
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }
}
