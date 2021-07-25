using System;
using System.Collections;
using System.Text;

namespace CriptografiaSimetricaWeb.Algoritmos
{
    class Des
    {
        //Stopwatch sw = new Stopwatch(); //Calcula o tempo de execução
        public Encoding ISO { get; set; }

        public Des()
        {
            ISO = Encoding.GetEncoding("ISO-8859-1"); //Codificação 
        }

        #region Criptrografia de arquivos

        public byte[] DecriptacaoArquivos(byte[] b, string chave)
        {
            b = DecriptacaoBytes(b, Estaticos.ConvHexByte(chave));

            return Estaticos.ReorganizaBlocos(b); //Reorganiza os bytes no tamanho original
        }

        public byte[] EncriptacaoArquivos(byte[] b, string chave)
        {
            b = Estaticos.OrganizarBlocos(b, 8); //Organiza os bytes em múltiplos de 8 (múltiplos de 64 bits).

            return EncriptacaoBytes(b, Estaticos.ConvHexByte(chave));
        }

        #endregion

        #region Criptografia de textos

        public string DecriptacaoTexto(string texto, string chave) //Retorna a decriptaçãodo do texto
        {
            byte[] b = ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            b = Estaticos.DesCorrigeISO(b); //Desfaz a função "CorrigeISO"
            b = DecriptacaoBytes(b, Estaticos.ConvHexByte(chave)); //Retorna os bytes Decriptados
            b = Estaticos.ReorganizaBlocos(b); //Reorganiza os bytes no tamanho original

            return ISO.GetString(b); //Converte os bytes em uma string
        }

        public string EncriptacaoTexto(string texto, string chave) //Retorna a decriptação do texto
        {
            byte[] b = ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            b = Estaticos.OrganizarBlocos(b, 8); //Organiza os bytes em múltiplos de 8 (múltiplos de 64 bits).
            b = EncriptacaoBytes(b, Estaticos.ConvHexByte(chave)); //Retorna os bytes Encriptados
            b = Estaticos.CorrigeISO(b); //Evita caracteres problemáticos da codificação ISO Latin-1

            return ISO.GetString(b); //Converte os bytes em uma string
        }

        #endregion

        #region Criptrografia DES (Em bytes)

        public byte[] DecriptacaoBytes(byte[] b, byte[] chave) //Retorna a decriptação em booleano de todos os blocos do texto (texto claro)
        {
            bool[] dados = ConvByteBool(b); //Converte um bloco de texto claro de qualquer tamanho em bits (bool)
            bool[] dados64Chave = ConvByteBool(chave); //Converte os bytes em uma chave de 64 bits (bool)

            int tam = dados.Length; //Tamanho dos dados múltiplos de 64
            bool[] bloco64 = new bool[64];
            bool[,] chaves = Chaves(dados64Chave); //Retorna as 16 chaves

            for (int i = 0; i < tam; i++)
            {
                bloco64[i % 64] = dados[i]; //Separa em blocos de 64 bits

                if (i % 64 == 63) //Faz a encriptação de cada bloco
                {
                    bloco64 = DecriptarBloco(bloco64, chaves); //Bloco decriptado (texto claro)

                    for (int j = 0; j < 64; j++)
                        dados[(i - 63) + j] = bloco64[j]; //Insere o bloco decriptado nos dados
                }
            }

            return ConvBoolByte(dados); //Converte os bits (bool) em um conjunto de bytes
        }

        public byte[] EncriptacaoBytes(byte[] b, byte[] chave) //Retorna a encriptação em booleano de todos os blocos do texto (texto cifrado)
        {
            bool[] dados = ConvByteBool(b); //Converte o conjunto de bytes em bits (bool)
            bool[] dados64Chave = ConvByteBool(chave); //Converte os bytes em uma chave de 64 bits (bool)
            
            int tam = dados.Length; //Tamanho dos dados múltiplos de 64
            bool[] bloco64 = new bool[64];
            bool[,] chaves = Chaves(dados64Chave); //Retorna as 16 chaves

            for (int i = 0; i < tam; i++)
            {
                bloco64[i % 64] = dados[i]; //Separa em blocos de 64 bits

                if (i % 64 == 63) //Faz a encriptação de cada bloco
                {
                    bloco64 = EncriptarBloco(bloco64, chaves); //Bloco criptografado

                    for (int j = 0; j < 64; j++)
                        dados[(i - 63) + j] = bloco64[j]; //Insere o bloco criptografado nos dados
                }
            }

            return ConvBoolByte(dados); //Converte os bits (bool) em um conjunto de bytes;
        }

        private bool[,] Chaves(bool[] dados64Chave) //Retorna as 16 chaves
        {
            bool[] CnDn_56, Kn;
            bool[,] chaves = new bool[16, 48];

            CnDn_56 = ConvChaveDados56(dados64Chave); //Escolha permutada 1

            for (int i = 0; i < 16; i++) //Realiza o armazenamento das 16 chaves
            {
                CnDn_56 = DeslocamentoCircularChave(CnDn_56, i); //CnDn de 56 bits
                Kn = ConvChaveDados48(CnDn_56); //Kn de 48 bits

                for (int j = 0; j < 48; j++) //Armazena as 16 chaves
                    chaves[i, j] = Kn[j];
            }

            return chaves;
        }
                
        private bool[] DecriptarBloco(bool[] dados64Crip, bool[,] chaves) //Retorna a decriptação de um bloco de 64 bits
        {
            bool[] Kn = new bool[48];
            bool[] dados64;

            dados64 = PermutacaoInicial(dados64Crip); //Permutação Inicial IP

            for (int i = 15; i >= 0; i--) //Execulta as 16 rodadas com as chaves na ordem oposta
            {
                for (int j = 0; j < 48; j++)
                    Kn[j] = chaves[i, j]; //Obtém a chave da vez Kn

                dados64 = Rodadas(dados64, Kn);
            }

            dados64 = Troca(dados64); //Troca de 32 bits

            return PermutacaoFinal(dados64); //Permutação Final (inicial reversa) IP^(-1)
        }

        private bool[] EncriptarBloco(bool[] dados64, bool[,] chaves) //Retorna a encriptação de um bloco de 64 bits
        {
            bool[] Kn = new bool[48];

            dados64 = PermutacaoInicial(dados64); //Permutação Inicial IP

            for (int i = 0; i < 16; i++) //Execulta as 16 rodadas
            {
                for (int j = 0; j < 48; j++)
                    Kn[j] = chaves[i, j]; //Obtém a chave da vez Kn

                dados64 = Rodadas(dados64, Kn);
            }

            dados64 = Troca(dados64); //Troca de 32 bits

            return PermutacaoFinal(dados64); //Permutação Final (inicial reversa) IP^(-1)
        }

        private bool[] PermutacaoInicial(bool[] dados64Texto) //Permutação Inicial
        {
            bool[] dados64 = new bool[64];

            int[] ip = {
                58, 50, 42, 34, 26, 18, 10, 02,
                60, 52, 44, 36, 28, 20, 12, 04,
                62, 54, 46, 38, 30, 22, 14, 06,
                64, 56, 48, 40, 32, 24, 16, 08,
                57, 49, 41, 33, 25, 17, 09, 01,
                59, 51, 43, 35, 27, 19, 11, 03,
                61, 53, 45, 37, 29, 21, 13, 05,
                63, 55, 47, 39, 31, 23, 15, 07
            };

            for (int i = 0; i < 64; i++)
                dados64[i] = dados64Texto[ip[i] - 1];

            return dados64;
        }

        private bool[] PermutacaoFinal(bool[] dados64Texto) //Permutação Final IP^(-1)
        {
            bool[] dados64 = new bool[64];

            int[] ip = {
                40, 08, 48, 16, 56, 24, 64, 32,
                39, 07, 47, 15, 55, 23, 63, 31,
                38, 06, 46, 14, 54, 22, 62, 30,
                37, 05, 45, 13, 53, 21, 61, 29,
                36, 04, 44, 12, 52, 20, 60, 28,
                35, 03, 43, 11, 51, 19, 59, 27,
                34, 02, 42, 10, 50, 18, 58, 26,
                33, 01, 41, 09, 49, 17, 57, 25
            };

            for (int i = 0; i < 64; i++)
                dados64[i] = dados64Texto[ip[i] - 1];

            return dados64;
        }

        #endregion

        #region Rodadas

        private bool[] Rodadas(bool[] dados64, bool[] chave)
        {
            bool[] le = new bool[32];
            bool[] re = new bool[32];

            for (int i = 0; i < 32; i++) //Divisão da primeira metade
                le[i] = dados64[i];

            for (int i = 0; i < 32; i++) //Divisão da segunda metade
                re[i] = dados64[i + 32];

            bool[] leProx = re;
            bool[] reProx = ReProx(le, re, chave);

            for (int i = 0; i < 32; i++) //Concatenação da primeira metade
                dados64[i] = leProx[i];

            for (int i = 0; i < 32; i++) //Concatenação da segunda metade
                dados64[i + 32] = reProx[i];

            return dados64;
        }

        private bool[] Troca(bool[] dados64) //Troca de 32 bits. Ou a rodada 17 da Cifra de Feistel
        {
            bool[] op = new bool[32];

            for (int i = 0; i < 32; i++)
                op[i] = dados64[i];

            for (int i = 0; i < 32; i++)
                dados64[i] = dados64[i + 32];

            for (int i = 0; i < 32; i++)
                dados64[i + 32] = op[i];

            return dados64;
        }

        private bool[] ReProx(bool[] le, bool[] re, bool[] chave) //Gerar o próximo RE
        {
            bool[] dados32 = new bool[32];

            bool[] funcao = Funcao(re, chave);

            for (int i = 0; i < 32; i++) //Operação de XOR
                dados32[i] = le[i] ^ funcao[i];

            return dados32;
        }

        #endregion

        #region Função

        private bool[] Funcao(bool[] re, bool[] chave)
        {
            bool[] xor48 = new bool[48];

            bool[] re48 = Expancao48(re); //Expanção para 48 bits

            for (int i = 0; i < 48; i++) //Operação de XOR
                xor48[i] = chave[i] ^ re48[i];

            bool[] dados32 = Reducao32(xor48); //Redução para 32 bits

            dados32 = FuncaoPermutacao(dados32); //O último passo da função

            return dados32;
        }

        private bool[] FuncaoPermutacao(bool[] dados32) //O último passo da função é a permutação
        {
            bool[] ret32 = new bool[32]; //Retorno da função

            int[] P =
            {
                16, 07, 20, 21,
                29, 12, 28, 17,
                01, 15, 23, 26,
                05, 18, 31, 10,
                02, 08, 24, 14,
                32, 27, 03, 09,
                19, 13, 30, 06,
                22, 11, 04, 25
            };

            for (int i = 0; i < 32; i++)
                ret32[i] = dados32[P[i] - 1];

            return ret32;
        }

        private bool[] Reducao32(bool[] xor48) //Dininuir de 48 bits para 32 bits (aplicação de oito S-boxes)
        {
            bool[] dados32 = new bool[32];

            int[,,] Sbox =
            {
                { //S1
                { 14, 04, 13, 01, 02, 15, 11, 08, 03, 10, 06, 12, 05, 09, 00, 07 },
                { 00, 15, 07, 04, 14, 02, 13, 01, 10, 06, 12, 11, 09, 05, 03, 08 },
                { 04, 01, 14, 08, 13, 06, 02, 11, 15, 12, 09, 07, 03, 10, 05, 00 },
                { 15, 12, 08, 02, 04, 09, 01, 07, 05, 11, 03, 14, 10, 00, 06, 13 } },
                { //S2
                { 15, 01, 08, 14, 06, 11, 03, 04, 09, 07, 02, 13, 12, 00, 05, 10 },
                { 03, 13, 04, 07, 15, 02, 08, 14, 12, 00, 01, 10, 06, 09, 11, 05 },
                { 00, 14, 07, 11, 10, 04, 13, 01, 05, 08, 12, 06, 09, 03, 02, 15 },
                { 13, 08, 10, 01, 03, 15, 04, 02, 11, 06, 07, 12, 00, 05, 14, 09 } },
                { //S3
                { 10, 00, 09, 14, 06, 03, 15, 05, 01, 13, 12, 07, 11, 04, 02, 08 },
                { 13, 07, 00, 09, 03, 04, 06, 10, 02, 08, 05, 14, 12, 11, 15, 01 },
                { 13, 06, 04, 09, 08, 15, 03, 00, 11, 01, 02, 12, 05, 10, 14, 07 },
                { 01, 10, 13, 00, 06, 09, 08, 07, 04, 15, 14, 03, 11, 05, 02, 12 } },
                { //S4
                { 07, 13, 14, 03, 00, 06, 09, 10, 01, 02, 08, 05, 11, 12, 04, 15 },
                { 13, 08, 11, 05, 06, 15, 00, 03, 04, 07, 02, 12, 01, 10, 14, 09 },
                { 10, 06, 09, 00, 12, 11, 07, 13, 15, 01, 03, 14, 05, 02, 08, 04 },
                { 03, 15, 00, 06, 10, 01, 13, 08, 09, 04, 05, 11, 12, 07, 02, 14 } },
                { //S5
                { 02, 12, 04, 01, 07, 10, 11, 06, 08, 05, 03, 15, 13, 00, 14, 09 },
                { 14, 11, 02, 12, 04, 07, 13, 01, 05, 00, 15, 10, 03, 09, 08, 06 },
                { 04, 02, 01, 11, 10, 13, 07, 08, 15, 09, 12, 05, 06, 03, 00, 14 },
                { 11, 08, 12, 07, 01, 14, 02, 13, 06, 15, 00, 09, 10, 04, 05, 03 } },
                { //S6
                { 12, 01, 10, 15, 09, 02, 06, 08, 00, 13, 03, 04, 14, 07, 05, 11 },
                { 10, 15, 04, 02, 07, 12, 09, 05, 06, 01, 13, 14, 00, 11, 03, 08 },
                { 09, 14, 15, 05, 02, 08, 12, 03, 07, 00, 04, 10, 01, 13, 11, 06 },
                { 04, 03, 02, 12, 09, 05, 15, 10, 11, 14, 01, 07, 06, 00, 08, 13 } },
                { //S7
                { 04, 11, 02, 14, 15, 00, 08, 13, 03, 12, 09, 07, 05, 10, 06, 01 },
                { 13, 00, 11, 07, 04, 09, 01, 10, 14, 03, 05, 12, 02, 15, 08, 06 },
                { 01, 04, 11, 13, 12, 03, 07, 14, 10, 15, 06, 08, 00, 05, 09, 02 },
                { 06, 11, 13, 08, 01, 04, 10, 07, 09, 05, 00, 15, 14, 02, 03, 12 } },
                { //S8
                { 13, 02, 08, 04, 06, 15, 11, 01, 10, 09, 03, 14, 05, 00, 12, 07 },
                { 01, 15, 13, 08, 10, 03, 07, 04, 12, 05, 06, 11, 00, 14, 09, 02 },
                { 07, 11, 04, 01, 09, 12, 14, 02, 00, 06, 10, 13, 15, 03, 05, 08 },
                { 02, 01, 14, 07, 04, 10, 08, 13, 15, 12, 09, 00, 03, 05, 06, 11 } },
            }; //Tabela de S-box [Sn, linha, coluna]

            int resto, linha, coluna, valor, cont = 0, sn = 0;
            BitArray linhaA = new BitArray(2);
            BitArray colunaA = new BitArray(4);

            for (int k = 0; k < 48; k++)
            {
                resto = k % 6;

                if (resto == 0) //Armazena o valor do bit no array linha
                    linhaA[1] = xor48[k];
                else if (resto == 5) //Armazena o valor do bit no array linha
                    linhaA[0] = xor48[k];
                else if (resto == 1) //Armazena o valor do bit no array coluna
                    colunaA[3] = xor48[k];
                else if (resto == 2) //Armazena o valor do bit no array coluna
                    colunaA[2] = xor48[k];
                else if (resto == 3) //Armazena o valor do bit no array coluna
                    colunaA[1] = xor48[k];
                else if (resto == 4) //Armazena o valor do bit no array coluna
                    colunaA[0] = xor48[k];

                if (resto == 5) //Armazena e reinicia
                {
                    linha = ConvBitArrayToInt32(linhaA); //Obtém o valor da linha
                    coluna = ConvBitArrayToInt32(colunaA); //Obtém o valor da coluna
                    valor = Sbox[sn, linha, coluna]; //Obtém o valor inteiro de 4 bits da tabela S1
                    byte b = Convert.ToByte(valor);

                    for (int i = 3; i >= 0; i--)
                    {
                        dados32[cont] = ((b >> i) & 1) != 0; //Obtem o valor do bit dentro do byte
                        cont++;
                    }

                    sn++; //Próximo Sn
                }
            }

            return dados32;
        }

        private bool[] Expancao48(bool[] re) //RE precisa aumentar de 32 bits para 48 bits
        {
            bool[] dados48 = new bool[48];

            int[] table = {
                32, 01, 02, 03, 04, 05,
                04, 05, 06, 07, 08, 09,
                08, 09, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 01
            }; //E BIT-SELECTION TABLE

            for (int i = 0; i < 48; i++)
                dados48[i] = re[table[i] - 1];

            return dados48;
        }

        #endregion

        #region Geração de Chaves K

        private bool[] ConvChaveDados48(bool[] dados56Chave) //Escolha permutada 2
        {
            bool[] dados48 = new bool[48];

            int[] pc2 = {
                14, 17, 11, 24, 01, 05,
                03, 28, 15, 06, 21, 10,
                23, 19, 12, 04, 26, 08,
                16, 07, 27, 20, 13, 02,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
            };

            for (int i = 0; i < 48; i++)
                dados48[i] = dados56Chave[pc2[i] - 1];

            return dados48;
        }

        private bool[] DeslocamentoCircularChave(bool[] dados56Chave, int n) //Deslocamento circular à esquerda
        {
            //O n é o número da interação de chaves, ex: k1, k2... kn

            bool[] C = new bool[28];
            bool[] D = new bool[28];

            for (int i = 0; i < 28; i++) //Divisão da primeira metade
                C[i] = dados56Chave[i];

            for (int i = 0; i < 28; i++) //Divisão da segunda metade
                D[i] = dados56Chave[i + 28];

            C = DeslocamentoChaveMetade(C, n);
            D = DeslocamentoChaveMetade(D, n);

            for (int i = 0; i < 28; i++) //Concatenação da primeira metade
                dados56Chave[i] = C[i];

            for (int i = 0; i < 28; i++) //Concatenação da segunda metade
                dados56Chave[i + 28] = D[i];

            return dados56Chave;
        }

        private bool[] DeslocamentoChaveMetade(bool[] dados28Chave, int n) //Deslocamento da metade da chave
        {
            bool[] ret = new bool[28]; //Retorno da função
            int[] n_desl = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; //Número de deslocamentos, 1 ou 2. Com 16 interações segundo o DES.
            int index;

            for (int i = 0; i < 28; i++)
            {
                index = i - n_desl[n];

                if (index < 0)
                    index = 28 + index;

                ret[index] = dados28Chave[i];
            }

            return ret;
        }

        private bool[] ConvChaveDados56(bool[] dados64Chave) //Escolha permutada 1
        {
            bool[] dados56 = new bool[56];

            int[] pc1 = {
                57, 49, 41, 33, 25, 17, 09,
                01, 58, 50, 42, 34, 26, 18,
                10, 02, 59, 51, 43, 35, 27,
                19, 11, 03, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                07, 62, 54, 46, 38, 30, 22,
                14, 06, 61, 53, 45, 37, 29,
                21, 13, 05, 28, 20, 12, 04
            };

            for (int i = 0; i < 56; i++)
                dados56[i] = dados64Chave[pc1[i] - 1];

            return dados56;
        }

        #endregion

        #region Conversões

        private int ConvBitArrayToInt32(BitArray bitArray) //Converte array de bit para inteiro
        {
            if (bitArray.Length > 32)
                throw new ArgumentException("O comprimento do argumento deve ser de no máximo 32 bits.");

            int[] array = new int[1];
            bitArray.CopyTo(array, 0);

            return array[0];
        }

        private bool[] ConvByteBool(byte[] bytes) //Converte um conjunto de bytes em dados do tipo booleano
        {
            int tam = bytes.Length * 8, cont = 0;
            bool[] dados = new bool[tam];

            foreach (var b in bytes)
            {
                for (int i = 7; i >= 0; i--)
                {
                    dados[cont] = ((b >> i) & 1) != 0;
                    cont++;
                }
            }

            return dados;
        }

        private byte[] ConvBoolByte(bool[] dados) //Converte dados do tipo booleano em um conjunto de bytes
        {
            int tam = dados.Length, //Tamanho em bits
                cont = 0,  //Contador do array de bytes
                resto;

            byte[] bytes = new byte[tam / 8];

            BitArray bit8 = new BitArray(8);

            for (int i = 0; i < tam; i++)
            {
                resto = i % 8;

                bit8[resto] = dados[i];

                if (resto == 7) //Execulta na oitava interação ou múltiplos de 7
                {
                    for (int j = 0; j < 4; j++) //O bit8 deve ser invertido execultar o CopyTo corretamente
                    {
                        bool bit = bit8[j];
                        bit8[j] = bit8[8 - j - 1];
                        bit8[8 - j - 1] = bit;
                    }

                    bit8.CopyTo(bytes, cont);

                    cont++; //Próximo byte
                }
            }

            return bytes;
        }

        #endregion

        private void ImprimeBin(bool[] dados, int separar) //Imprime os valores em binário
        {
            for (int i = 0; i < dados.Length; i++)
            {
                if (i % separar == 0 && i > 0)
                    Console.Write(" ");

                if (dados[i] == true)
                    Console.Write("1");
                else
                    Console.Write("0");
            }

            Console.WriteLine();
        }
    }
}
