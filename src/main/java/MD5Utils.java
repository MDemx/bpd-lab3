import org.apache.commons.lang3.ArrayUtils;
public class MD5Utils {
    private static final int INITIAL_A = 0x67452301;
    private static final int INITIAL_B = (int) 0xEFCDAB89L;
    private static final int INITIAL_C = (int) 0x98BADCFEL;
    private static final int INITIAL_D = 0x10325476;

    private static final int[] TABLE_T = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    private static final int[] SHIFT_AMTS = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};

    private static byte[] step1(final byte[] data) {
        int bytesToAdd = (448 - data.length * 8 % 512) / 8;

        if (bytesToAdd <= 0) {
            bytesToAdd = 64 + (bytesToAdd);
        }

        byte[] extended = new byte[bytesToAdd];
        extended[0] = (byte) 0x80;

        return ArrayUtils.addAll(data, extended);
    }

    private static byte[] step2(final byte[] data, int initialBytesLength) {
        byte[] result = new byte[data.length + 8];
        System.arraycopy(data, 0, result, 0, data.length);

        long messageLenBits = initialBytesLength * 8L;

        for (int i = result.length - 8; i < result.length; i++) {
            result[i] = (byte) messageLenBits;
            messageLenBits >>>= 8;
        }

        return result;
    }

    private static byte[] step3(final byte[] data) {
        int numberOfBlocks = data.length * 8 / 512;
        int[] buffer = new int[16];

        int a = INITIAL_A;
        int b = INITIAL_B;
        int c = INITIAL_C;
        int d = INITIAL_D;

        for (int i = 0; i < numberOfBlocks; i++) {
            int index = i * 64;

            for (int j = 0; j < 64; j++, index++) {
                buffer[j >> 2] = (data[index] << 24) | (buffer[j >> 2] >>> 8);
            }

            int originalA = a;
            int originalB = b;
            int originalC = c;
            int originalD = d;

            for (int j = 0; j < 64; j++) {
                int div16 = j >>> 4;
                int f = 0;
                int bufferIndex = j;

                switch (div16) {
                    case 0:
                        f = (b & c) | (~b & d);
                        break;

                    case 1:
                        f = (b & d) | (c & ~d);
                        bufferIndex = (bufferIndex * 5 + 1) & 0x0F;
                        break;

                    case 2:
                        f = b ^ c ^ d;
                        bufferIndex = (bufferIndex * 3 + 5) & 0x0F;
                        break;

                    case 3:
                        f = c ^ (b | ~d);
                        bufferIndex = (bufferIndex * 7) & 0x0F;
                        break;
                }

                int temp = b + Integer.rotateLeft(
                        a + f + buffer[bufferIndex] + TABLE_T[j],
                        SHIFT_AMTS[(div16 << 2) | (j & 3)]);

                a = d;
                d = c;
                c = b;
                b = temp;
            }

            a += originalA;
            b += originalB;
            c += originalC;
            d += originalD;
        }

        byte[] md5 = new byte[16];
        int count = 0;

        for (int i = 0; i < 4; i++) {
            int n = (i == 0) ? a : ((i == 1) ? b : ((i == 2) ? c : d));

            for (int j = 0; j < 4; j++) {
                md5[count++] = (byte) n;
                n >>>= 8;
            }
        }

        return md5;
    }

    public static byte[] md5(byte[] message) {
        byte[] step1 = step1(message);
        byte[] step2 = step2(step1, message.length);

        return step3(step2);
    }
}
