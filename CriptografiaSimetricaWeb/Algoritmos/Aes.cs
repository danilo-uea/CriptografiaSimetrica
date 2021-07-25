using System.Text;

namespace CriptografiaSimetricaWeb.Algoritmos
{
    class Aes
    {
        #region Criptrografia de arquivos

        public byte[] DecriptacaoArquivos(byte[] b, string chave)
        {
            return DecriptacaoBytes(b, Estaticos.ConvHexByte(chave));
        }

        public byte[] EncriptacaoArquivos(byte[] b, string chave)
        {
            return EncriptacaoBytes(b, Estaticos.ConvHexByte(chave));
        }

        #endregion

        #region Criptografia de textos

        public string DecriptacaoTexto(string texto, string chave) //Retorna a decriptaçãodo do texto
        {
            byte[] b = ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            b = Estaticos.DesCorrigeISO(b); //Desfaz a função "CorrigeISO"
            b = DecriptacaoBytes(b, Estaticos.ConvHexByte(chave)); //Retorna os bytes Decriptados

            return ISO.GetString(b); //Converte os bytes em uma string
        }

        public string EncriptacaoTexto(string texto, string chave) //Retorna a decriptação do texto
        {
            byte[] b = ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            b = EncriptacaoBytes(b, Estaticos.ConvHexByte(chave)); //Retorna os bytes Encriptados
            b = Estaticos.CorrigeISO(b); //Evita caracteres problemáticos da codificação ISO Latin-1

            return ISO.GetString(b); //Converte os bytes em uma string
        }

        #endregion

        public Encoding ISO { get; set; }

        private byte[,] w { get; set; }

        private byte[,] Rcon;

        private byte[,] sBox =
        {
            { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, },
            { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, },
            { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, },
            { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, },
            { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, },
            { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, },
            { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, },
            { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, },
            { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, },
            { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, },
            { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, },
            { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, },
            { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, },
            { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, },
            { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, },
            { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16, },
        };

        private byte[,] sBoxInv =
        {
            { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, },
            { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, },
            { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, },
            { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, },
            { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, },
            { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, },
            { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, },
            { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, },
            { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, },
            { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, },
            { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, },
            { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, },
            { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, },
            { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, },
            { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, },
            { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D, },
        };

        private byte[,] tabMixColumns =
        {
            { 0x02, 0x03, 0x01, 0x01 },
            { 0x01, 0x02, 0x03, 0x01 },
            { 0x01, 0x01, 0x02, 0x03 },
            { 0x03, 0x01, 0x01, 0x02 },
        };

        private byte[,] tabMixColumnsInv =
        {
            { 0x0E, 0x0B, 0x0D, 0x09 },
            { 0x09, 0x0E, 0x0B, 0x0D },
            { 0x0D, 0x09, 0x0E, 0x0B },
            { 0x0B, 0x0D, 0x09, 0x0E },
        };

        public Aes()
        {
            ISO = Encoding.GetEncoding("ISO-8859-1"); //Codificação 
            RC();
        }

        private byte[] EncriptacaoBytes(byte[] dados, byte[] chave)
        {
            dados = Estaticos.OrganizarBlocos(dados, 16); //Organiza os bytes em múltiplos de 16 bytes
            KeyExpansion(chave); //Gera as 44 palavras da chave
            int tam = dados.Length; //Quantidade de bytes
            byte[,] estado = new byte[4, 4];
            int l, c;

            for (int i = 0; i < tam; i++)
            {
                l = (i / 4) % 4; //linha
                c = i % 4;       //coluna
                estado[c, l] = dados[i]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna

                if (l == 3 && c == 3) //Encriptar bloco
                {
                    estado = EncriptarBloco(estado); //Bloco criptografado

                    for (int j = 0; j < 4; j++)
                    {
                        for (int k = 0; k < 4; k++)
                        {
                            dados[(i - 15) + (j * 4 + k)] = estado[k, j]; //Devolve o bloco criptografado nos dados na mesma posição
                        }
                    }
                }
            }

            return dados;
        }

        private byte[] DecriptacaoBytes(byte[] dados, byte[] chave)
        {
            KeyExpansion(chave); //Gera as 44 palavras da chave
            int tam = dados.Length; //Quantidade de bytes
            byte[,] estado = new byte[4, 4];
            int l, c;

            for (int i = 0; i < tam; i++)
            {
                l = (i / 4) % 4; //linha
                c = i % 4;       //coluna
                estado[c, l] = dados[i]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna

                if (l == 3 && c == 3) //Encriptar bloco
                {
                    estado = DecriptarBloco(estado); //Bloco decriptado

                    for (int j = 0; j < 4; j++)
                    {
                        for (int k = 0; k < 4; k++)
                        {
                            dados[(i - 15) + (j * 4 + k)] = estado[k, j]; //Devolve o bloco criptografado nos dados na mesma posição
                        }
                    }
                }
            }

            return Estaticos.ReorganizaBlocos(dados); //Reorganiza os bytes no tamanho original
        }

        private byte[,] EncriptarBloco(byte[,] estado)
        {
            byte[,] chave = new byte[4, 4];

            for (int i = 0; i < 4; i++) //Primeira chave
            {
                for (int j = 0; j < 4; j++)
                {
                    chave[i, j] = w[j, i]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna
                }
            }

            estado = AddRoundKey(estado, chave); //Rodada Inicial 0

            for (int i = 1; i <= 9; i++) //Rodada i
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        chave[j, k] = w[k + i * 4, j]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna
                    }
                }

                estado = SubBytes(estado);
                estado = ShiftRows(estado);
                estado = MixColumns(estado);
                estado = AddRoundKey(estado, chave);
            }

            for (int j = 0; j < 4; j++) //Última chave
            {
                for (int k = 0; k < 4; k++)
                {
                    chave[j, k] = w[k + 40, j]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna
                }
            }

            estado = SubBytes(estado);
            estado = ShiftRows(estado);
            estado = AddRoundKey(estado, chave); //Rodada Final 10 (sem o MixColumns)

            return estado;
        }

        private byte[,] DecriptarBloco(byte[,] estado)
        {
            byte[,] chave = new byte[4, 4];

            for (int j = 0; j < 4; j++) //Última chave
            {
                for (int k = 0; k < 4; k++)
                {
                    chave[j, k] = w[k + 40, j]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna
                }
            }

            estado = AddRoundKey(estado, chave); //Rodada Final 10 (sem o MixColumns)

            for (int i = 9; i >= 1; i--) //Rodada i
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        chave[j, k] = w[k + i * 4, j]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna
                    }
                }

                estado = ShiftRowsInv(estado);
                estado = SubBytesInv(estado);
                estado = AddRoundKey(estado, chave);
                estado = MixColumnsInv(estado);
            }

            for (int i = 0; i < 4; i++) //Primeira chave
            {
                for (int j = 0; j < 4; j++)
                {
                    chave[i, j] = w[j, i]; //Linha e coluna invertidos. Pois cada palavra é representada em coluna
                }
            }

            estado = ShiftRowsInv(estado);
            estado = SubBytesInv(estado);
            estado = AddRoundKey(estado, chave);

            return estado;
        }

        private void KeyExpansion (byte[] key) //Expansão da chave de 4 palavras para 44 palavras
        {
            w = new byte[44, 4]; //44 palavras
            byte[] temp, op;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    w[i, j] = key[4 * i + j];
            }

            for (int i = 4; i < 44; i++)
            {
                temp = w.GetRow(i - 1); //Obtem a linha completa (palavra) do array w

                if (i % 4 == 0)
                    temp = Xor(SubWord(RotWord(temp)), Rcon.GetRow(i / 4));

                op = Xor(w.GetRow(i - 4), temp);

                for (int j = 0; j < 4; j++)
                    w[i, j] = op[j];
            }
        }

        private byte[] RotWord(byte[] palavra)  //Realiza um deslocamento circular de um byte à esquerda em uma word
        {
            byte[] ret = new byte[4];

            for (int i = 0; i < 4; i++)
                ret[i] = palavra[(i + 1) % 4];

            return ret;
        }

        private byte[] SubWord(byte[] palavra) //Realiza uma substituição byte a byte de sua word de entrada, usando a S-box
        {
            byte[] ret = new byte[4];
            int linha, coluna;

            for (int i = 0; i < 4; i++)
            {
                linha = (byte)(palavra[i] >> 4);  //Obtém o valor dos quatro bits a esqueda
                coluna = (byte)(palavra[i] & 15); //Obtém o valor dos quatro bits a direita
                ret[i] = sBox[linha, coluna];
            }

            return ret;
        }

        private byte[] Xor(byte[] a, byte[] b) //Operação de XOR de cada Word (palavra de 4 bytes)
        {
            byte[] op = new byte[4];

            for (int i = 0; i < 4; i++)
            {
                op[i] = (byte)(a[i] ^ b[i]);
            }

            return op;
        }

        private void RC() //Preenche o array de Word chamado Rcon
        {
            Rcon = new byte[11, 4];

            Rcon[0, 0] = 0x00;
            Rcon[0, 1] = 0x00;
            Rcon[0, 2] = 0x00;
            Rcon[0, 3] = 0x00;

            Rcon[1, 0] = 0x01;
            Rcon[1, 1] = 0x00;
            Rcon[1, 2] = 0x00;
            Rcon[1, 3] = 0x00;

            Rcon[2, 0] = 0x02;
            Rcon[2, 1] = 0x00;
            Rcon[2, 2] = 0x00;
            Rcon[2, 3] = 0x00;

            Rcon[3, 0] = 0x04;
            Rcon[3, 1] = 0x00;
            Rcon[3, 2] = 0x00;
            Rcon[3, 3] = 0x00;

            Rcon[4, 0] = 0x08;
            Rcon[4, 1] = 0x00;
            Rcon[4, 2] = 0x00;
            Rcon[4, 3] = 0x00;

            Rcon[5, 0] = 0x10;
            Rcon[5, 1] = 0x00;
            Rcon[5, 2] = 0x00;
            Rcon[5, 3] = 0x00;

            Rcon[6, 0] = 0x20;
            Rcon[6, 1] = 0x00;
            Rcon[6, 2] = 0x00;
            Rcon[6, 3] = 0x00;

            Rcon[7, 0] = 0x40;
            Rcon[7, 1] = 0x00;
            Rcon[7, 2] = 0x00;
            Rcon[7, 3] = 0x00;

            Rcon[8, 0] = 0x80;
            Rcon[8, 1] = 0x00;
            Rcon[8, 2] = 0x00;
            Rcon[8, 3] = 0x00;

            Rcon[9, 0] = 0x1B;
            Rcon[9, 1] = 0x00;
            Rcon[9, 2] = 0x00;
            Rcon[9, 3] = 0x00;

            Rcon[10, 0] = 0x36;
            Rcon[10, 1] = 0x00;
            Rcon[10, 2] = 0x00;
            Rcon[10, 3] = 0x00;
        }

        private byte[,] AddRoundKey(byte[,] estado, byte[,] chave) //Operação de XOR do estado com a chave da rodada
        {
            byte[,] ret = new byte[4, 4]; //Retorno

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ret[i, j] = (byte)(estado[i, j] ^ chave[i, j]);
                }
            }

            return ret;
        }

        private byte[,] MixColumns (byte[,] estado) //Embaralhamento de colunas
        {
            byte[,] ret = new byte[4, 4]; //Retorno

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ret[i,j] = 0;
                    for (int k = 0; k < 4; k++)
                        ret[i, j] = (byte)(ret[i, j] ^ MultGF(tabMixColumns[i, k], estado[k, j]));
                }
            }

            return ret;
        }

        private byte[,] MixColumnsInv(byte[,] estado)
        {
            byte[,] ret = new byte[4, 4]; //Retorno

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ret[i, j] = 0;
                    for (int k = 0; k < 4; k++)
                        ret[i, j] = (byte)(ret[i, j] ^ MultGF(tabMixColumnsInv[i, k], estado[k, j]));
                }
            }

            return ret;
        }

        private byte MultGF(byte a , byte b) //Multiplicação em GF(2^8)
        {
            bool b7;
            byte ret = 0;

            if (((a >> 0) & 1) != 0)
                ret = b;

            for (int i = 1; i < 8; i++)
            {
                b7 = b > 127; //Pega o valor de b7, o sétimo bit (mais significativo)
                b = (byte)(b << 1); //Deslocamento à esquerda por 1 bit
                
                if (b7) //Se b7 = 1, então a redução do módulo m(x) e obtida
                    b = (byte)(b ^ 27); //XOR bit a bit com (00011011), que representa (x4 + x3 + x + 1)

                if (((a >> i) & 1) != 0)
                    ret = (byte)(ret ^ b); //XOR final da multiplicação
            }

            return ret;
        }

        private byte[,] ShiftRows (byte[,] estado) //Descolamento das linhas à esquerda
        {
            byte[,] op = new byte[4, 4]; //Operador 4 X 4
            int coluna;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    coluna = (j + i) % 4;
                    op[i, j] = estado[i, coluna];
                }
            }

            return op;
        }

        private byte[,] ShiftRowsInv(byte[,] estado) //Descolamento das linhas à esquerda
        {
            byte[,] op = new byte[4, 4]; //Operador 4 X 4
            int coluna;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    coluna = (j - i) % 4;
                    if (coluna < 0)
                        coluna += 4;
                    op[i, j] = estado[i, coluna];
                }
            }

            return op;
        }

        private byte[,] SubBytes(byte[,] estado) //Transformação de SubBytes
        {
            byte[,] op = new byte[4, 4]; //Operador 4 X 4
            int linha, coluna;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    linha = (byte)(estado[i, j] >> 4);  //Obtém o valor dos quatro bits a esqueda
                    coluna = (byte)(estado[i, j] & 15); //Obtém o valor dos quatro bits a direita
                    op[i, j] = sBox[linha, coluna];
                }
            }

            return op;
        }

        private byte[,] SubBytesInv(byte[,] estado) //Transformação de SubBytes
        {
            byte[,] op = new byte[4, 4];
            int linha, coluna;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    linha = (byte)(estado[i, j] >> 4);  //Obtém o valor dos quatro bits a esqueda
                    coluna = (byte)(estado[i, j] & 15); //Obtém o valor dos quatro bits a direita
                    op[i, j] = sBoxInv[linha, coluna];
                }
            }

            return op;
        }
    }
}
