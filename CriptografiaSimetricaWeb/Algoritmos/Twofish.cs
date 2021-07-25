using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CriptografiaSimetricaWeb.Algoritmos
{
    class Twofish
    {
        private byte[] z = new byte[4];
        private uint t0, t1;
        private byte[] a = new byte[5];
        private byte[] b = new byte[5];
        //private bool crip; //Verifica se é encriptação (true) ou decriptação (false)

        private static readonly double dois_32 = Math.Pow(2, 32);

        private static readonly byte[,] mds =
        {
            { 0x01, 0xEF, 0x5B, 0x5B },
            { 0x5B, 0xEF, 0xEF, 0x01 },
            { 0xEF, 0x5B, 0x01, 0xEF },
            { 0xEF, 0x01, 0xEF, 0x5B }
        };

        private static readonly byte[,] rs =
        {
            { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E },
            { 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5 },
            { 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19 },
            { 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03 }
        };

        public static readonly byte[,] tQ0 = new byte[4, 16]
        {
            { 0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4 },
            { 0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD },
            { 0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1 },
            { 0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA }
        };

        public static readonly byte[,] tQ1 = new byte[4, 16]
        {
            { 0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5 },
            { 0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8 },
            { 0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF },
            { 0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA }
        };

        byte[] Key;
        uint[] K = new uint[40];
        byte[,] S = new byte[2, 4];

        public Encoding ISO { get; set; }

        #region Criptrografia de arquivos

        public byte[] DecriptacaoArquivos(byte[] b, string chave)
        {
            Key = Estaticos.ConvHexByte(chave);

            return Decriptacao(b);
        }

        public byte[] EncriptacaoArquivos(byte[] b, string chave)
        {
            Key = Estaticos.ConvHexByte(chave);

            return Encriptacao(b);
        }

        #endregion

        #region Criptografia de textos

        public string DecriptacaoTexto(string texto, string chave) //Retorna a decriptaçãodo do texto
        {
            Key = Estaticos.ConvHexByte(chave);
            byte[] b = ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            b = Estaticos.DesCorrigeISO(b); //Desfaz a função "CorrigeISO"
            b = Decriptacao(b); //Retorna os bytes Decriptados

            return ISO.GetString(b); //Converte os bytes em uma string
        }

        public string EncriptacaoTexto(string texto, string chave) //Retorna a decriptação do texto
        {
            Key = Estaticos.ConvHexByte(chave);
            byte[] b = ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            b = Encriptacao(b); //Retorna os bytes Encriptados
            b = Estaticos.CorrigeISO(b); //Evita caracteres problemáticos da codificação ISO Latin-1

            return ISO.GetString(b); //Converte os bytes em uma string
        }

        #endregion

        public Twofish()
        {
            ISO = Encoding.GetEncoding("ISO-8859-1"); //Codificação 
        }

        private void IniciaTwofish()
        {
            GenerationS();
            GenerationK();
        }

        public byte[] Encriptacao(byte[] data) //Execulta a encriptação
        {
            uint[] R = new uint[4]; //O bloco de 128 bits dividido em 4 partes de 32 bits
            uint C2 = 0, C3 = 0;
            int i, j, r;

            IniciaTwofish();
            data = Estaticos.OrganizarBlocos(data, 16); //Organiza os bytes em múltiplos de 16 bytes

            for (i = 0; i < data.Length; i++) //Realiza a encriptação de bloco em bloco de 128 bits (16 bytes)
            {
                for (j = 0; j < 4; j++)
                {
                    R[j] = (uint)((data[i++] << 24) | (data[i++] << 16) | (data[i++] << 8) | data[i++]);
                }

                //crip = true; //É a encriptação

                InputWhitening(ref R); //Resultado do Input

                for (r = 0; r < 16; r++) //Cada rodada da Encriptação
                {
                    FunctionF(ref R[0], ref R[1], out uint f0, out uint f1, r);
                    C2 = (f0 ^ R[2]);
                    //C2 = ROR(f0 ^ R[2], 1);
                    C3 = f1 ^ (R[3]);
                    //C3 = f1 ^ ROL(R[3], 1);
                    R[2] = R[0];
                    R[3] = R[1];
                    R[0] = C2;
                    R[1] = C3;
                }

                R[0] = R[2];
                R[1] = R[3];
                R[2] = C2;
                R[3] = C3;

                OutputWhitening(ref R);

                i = i - 16;

                data[i++] = (byte)(R[0] >> 24);
                data[i++] = (byte)(R[0] >> 16);
                data[i++] = (byte)(R[0] >> 8);
                data[i++] = (byte)(R[0]);
                data[i++] = (byte)(R[1] >> 24);
                data[i++] = (byte)(R[1] >> 16);
                data[i++] = (byte)(R[1] >> 8);
                data[i++] = (byte)(R[1]);
                data[i++] = (byte)(R[2] >> 24);
                data[i++] = (byte)(R[2] >> 16);
                data[i++] = (byte)(R[2] >> 8);
                data[i++] = (byte)(R[2]);
                data[i++] = (byte)(R[3] >> 24);
                data[i++] = (byte)(R[3] >> 16);
                data[i++] = (byte)(R[3] >> 8);
                data[i] = (byte)(R[3]);
            }

            return data;
        }

        public byte[] Decriptacao(byte[] data) //Execulta a decriptação
        {
            uint[] R = new uint[4]; //O bloco de 128 bits dividido em 4 partes de 32 bits
            uint C2 = 0, C3 = 0;
            int i, j, r;

            IniciaTwofish();

            for (i = 0; i < data.Length; i++) //Realiza a encriptação de bloco em bloco de 128 bits (16 bytes)
            {
                for (j = 0; j < 4; j++)
                {
                    R[j] = (uint)((data[i++] << 24) | (data[i++] << 16) | (data[i++] << 8) | data[i++]);
                }

                //crip = false; //É a decriptação

                OutputWhitening(ref R);

                for (r = 15; r >= 0; r--) //Cada rodada da Decriptação
                {
                    FunctionF(ref R[0], ref R[1], out uint f0, out uint f1, r);
                    C2 = (f0 ^ R[2]);
                    //C2 = ROL(f0 ^ R[2], 1);
                    C3 = f1 ^ (R[3]);
                    //C3 = f1 ^ ROR(R[3], 1);
                    R[2] = R[0];
                    R[3] = R[1];
                    R[0] = C2;
                    R[1] = C3;
                }

                R[0] = R[2];
                R[1] = R[3];
                R[2] = C2;
                R[3] = C3;

                InputWhitening(ref R); //Resultado do Input

                i = i - 16;

                data[i++] = (byte)(R[0] >> 24);
                data[i++] = (byte)(R[0] >> 16);
                data[i++] = (byte)(R[0] >> 8);
                data[i++] = (byte)(R[0]);
                data[i++] = (byte)(R[1] >> 24);
                data[i++] = (byte)(R[1] >> 16);
                data[i++] = (byte)(R[1] >> 8);
                data[i++] = (byte)(R[1]);
                data[i++] = (byte)(R[2] >> 24);
                data[i++] = (byte)(R[2] >> 16);
                data[i++] = (byte)(R[2] >> 8);
                data[i++] = (byte)(R[2]);
                data[i++] = (byte)(R[3] >> 24);
                data[i++] = (byte)(R[3] >> 16);
                data[i++] = (byte)(R[3] >> 8);
                data[i] = (byte)(R[3]);
            }

            return Estaticos.ReorganizaBlocos(data); //Reorganiza os bytes no tamanho original
        }

        private void FunctionH() //Para chave de 128 bits
        {
            byte[,] Meven = new byte[2, 4];
            byte[,] Modd = new byte[2, 4];
                        
            for (int i = 0; i < 4; i++) //M2
                Meven[0, i] = Key[i + 08];
            
            for (int i = 0; i < 4; i++) //M0
                Meven[1, i] = Key[i + 00];
            
            for (int i = 0; i < 4; i++) //M3
                Modd[0, i] = Key[i + 12];
            
            for (int i = 0; i < 4; i++) //M1
                Modd[1, i] = Key[i + 04];

            uint cima, baixo;

            for (uint i = 0; i < 20; i++)
            {
                cima = FunctionG(2 * i, ref Meven);
                baixo = FunctionG(2 * i + 1, ref Modd);
                ROL(ref baixo, 8);
                PHT(cima, baixo, out cima, out baixo);
                ROL(ref baixo, 9);
                K[2 * i] = cima;
                K[2 * i + 1] = baixo;
            }
        }

        private void GenerationK()
        {
            //crip = true;
            FunctionH();
        }

        private void GenerationS() //Gerar as duas sub-chaves S0 e S1
        {
            for (int i = 0; i < 4; i++)
            {
                S[0, i] = 0;

                for (int j = 0; j < 8; j++)
                {
                    S[0, i] = (byte)(S[0, i] ^ MultGF(rs[i, j], Key[j]));
                }
            }

            for (int i = 0; i < 4; i++)
            {
                S[1, i] = 0;

                for (int j = 0; j < 8; j++)
                {
                    S[1, i] = (byte)(S[1, i] ^ MultGF(rs[i, j], Key[j + 8]));
                }
            }
        }

        private void InputWhitening(ref uint[] P)
        {
            for (int j = 0; j < 4; j++)
            {
                P[j] ^= K[j];
            }
        }

        private void OutputWhitening(ref uint[] P)
        {
            for (int j = 0; j < 4; j++)
            {
                P[j] ^= K[j + 4];
            }
        }

        private void FunctionF(ref uint r0, ref uint r1, out uint f0, out uint f1, int round)
        {
            t0 = FunctionG(r0, ref S);
            //if (crip)
            //    ROL(ref r1, 8); //Encriptação
            //else
            //    ROR(ref r1, 8); //Decriptação
            t1 = FunctionG(r1, ref S);

            PHT(t0, t1, out f0, out f1);
            f0 = (uint)((f0 + K[2 * round + 8]) % dois_32);
            f1 = (uint)((f1 + K[2 * round + 9]) % dois_32);
        }

        private void PHT(uint t0, uint t1, out uint f0, out uint f1)
        {
            f0 = (uint)((t0 + t1) % dois_32);
            f1 = (uint)((t1 + f0) % dois_32);
        }

        private byte Q0(byte valor) //ok
        {
            a[0] = (byte)(valor >> 4);
            b[0] = (byte)(valor & 0x0F);

            a[1] = (byte)(a[0] ^ b[0]);
            //if (crip)
            //    ROR4(ref b[0], 1); //Encriptação
            //else
            //    ROL4(ref b[0], 1); //Decriptação
            b[1] = (byte)(a[0] ^ b[0] ^ ((8 * a[0]) % 16));

            a[2] = tQ0[0, a[1]]; //t0
            b[2] = tQ0[1, b[1]]; //t1

            a[3] = (byte)(a[2] ^ b[2]);
            //if (crip) 
            //    ROR4(ref b[2], 1); //Encriptação
            //else 
            //    ROL4(ref b[2], 1); //Decriptação
            b[3] = (byte)(a[1] ^ b[2]^ ((8 * a[2]) % 16));

            a[4] = tQ0[2, a[3]]; //t2
            b[4] = tQ0[3, b[3]]; //t3

            return (byte)((b[4] << 4) + a[4]);
        }

        private byte Q1(byte valor) //ok
        {
            byte[] a = new byte[5];
            byte[] b = new byte[5];

            a[0] = (byte)(valor >> 4);
            b[0] = (byte)(valor & 0x0F);

            a[1] = (byte)(a[0] ^ b[0]);
            //if (crip) 
            //    ROR4(ref b[0], 1); //Encriptação
            //else 
            //    ROL4(ref b[0], 1); //Decriptação
            b[1] = (byte)(a[0] ^ b[0] ^ ((8 * a[0]) % 16));

            a[2] = tQ1[0, a[1]]; //t0
            b[2] = tQ1[1, b[1]]; //t1

            a[3] = (byte)(a[2] ^ b[2]);
            //if (crip) 
            //    ROR4(ref b[2], 1); //Encriptação
            //else 
            //    ROL4(ref b[2], 1); //Decriptação
            b[3] = (byte)(a[1] ^ b[2] ^ ((8 * a[2]) % 16));

            a[4] = tQ1[2, a[3]]; //t2
            b[4] = tQ1[3, b[3]]; //t3

            return (byte)((b[4] << 4) + a[4]);
        }

        private void SBox(ref byte[] g, ref byte[,] M2x4) //ok
        {
            g[0] = (byte)(Q0(g[0]) ^ M2x4[0,0]);
            g[1] = (byte)(Q1(g[1]) ^ M2x4[0,1]);
            g[2] = (byte)(Q0(g[2]) ^ M2x4[0,2]);
            g[3] = (byte)(Q1(g[3]) ^ M2x4[0,3]);

            g[0] = (byte)(Q0(g[0]) ^ M2x4[1,0]);
            g[1] = (byte)(Q0(g[1]) ^ M2x4[1,1]);
            g[2] = (byte)(Q1(g[2]) ^ M2x4[1,2]);
            g[3] = (byte)(Q1(g[3]) ^ M2x4[1,3]);

            g[0] = Q1(g[0]);
            g[1] = Q0(g[1]);
            g[2] = Q1(g[2]);
            g[3] = Q0(g[3]);
        }

        private uint FunctionG(uint x, ref byte[,] M2x4)
        {
            byte[] g = new byte[4];

            g[3] = (byte)(x & 0x00FF);
            x >>= 8;
            g[2] = (byte)(x & 0x00FF);
            x >>= 8;
            g[1] = (byte)(x & 0x00FF);
            x >>= 8;
            g[0] = (byte)(x & 0x00FF);

            SBox(ref g, ref M2x4);

            return MDS(g);
        }

        private uint MDS(byte[] y)
        {
            for (int i = 0; i < 4; i++)
            {
                z[i] = 0;

                for (int j = 0; j < 4; j++)
                {
                    z[i] = (byte)(z[i] ^ MultGF(mds[i, j], y[j]));
                }
            }

            uint z32 = 0;

            for (int i = 0; i < 4; i++)
                z32 += (uint)(z[i] << (i * 8));

            return z32;
        }

        private byte MultGF(byte a, byte b) //Multiplicação em GF(2^8)
        {
            bool b7;
            byte ret = 0;

            if (((a >> 0) & 1) != 0)
                ret = b;

            for (int i = 1; i < 8; i++)
            {
                b7 = b > 127;
                b = (byte)(b << 1);

                if (b7)
                    b = (byte)(b ^ 27);

                if (((a >> i) & 1) != 0)
                    ret = (byte)(ret ^ b);
            }

            return ret;
        }

        private uint ROR(uint valor, int n) //Rotaciona n bits para a direita
        {
            return (valor >> n) | (valor << (32 - n));
        }

        private void ROR(ref uint valor, int n) //Rotaciona n bits para a direita
        {
            valor = (valor >> n) | (valor << (32 - n));
        }

        private uint ROL(uint valor, int n) //Rotaciona n bits para a esquerda
        {
            return (valor << n) | (valor >> (32 - n));
        }

        private void ROL(ref uint valor, int n) //Rotaciona n bits para a esquerda
        {
            valor = (valor << n) | (valor >> (32 - n));
        }

        private void ROR4(ref byte valor, int n) //Rotaciona n bits para a direita (em um espaço de 4 bits)
        {
            valor = (byte)((valor >> n | (valor << (4 - n))) & 0x0F);
        }

        private void ROL4(ref byte valor, int n) //Rotaciona n bits para a direita (em um espaço de 4 bits)
        {
            valor = (byte)((valor << n | (valor >> (4 - n))) & 0x0F);
        }
    }
}
