namespace SoftServeProject3.Api.Utils
{
    public class UsernameSearch
    {
        public static Int32 SearchDirectly(String a, String b)
        {

            if (string.IsNullOrEmpty(a))
            {
                if (!string.IsNullOrEmpty(b))
                {
                    return b.Length;
                }
                return 0;
            }

            if (string.IsNullOrEmpty(b))
            {
                if (!string.IsNullOrEmpty(a))
                {
                    return a.Length;
                }
                return 0;
            }

            Int32 result = 0;

            char[] charsA = a.ToCharArray();
            char[] charsB = b.ToCharArray();
            for (int i = 0; i < charsA.Length; i++)
            {
                if (i >= charsB.Length)
                    break;
                if (charsA[i].ToString().ToLower() == charsB[i].ToString().ToLower())
                    result += 1;
                else
                {
                    result = 0;
                    break;
                }

            }
            return result;
        }
    }
}
