using System;
using System.Collections.Generic;
using System.Text;

namespace CriptografiaSimetricaWeb.Algoritmos
{
    class TriploDes
    {
        private string Chave1 { get; set; }
        private string Chave2 { get; set; }
        private string Chave3 { get; set; }
        public bool Diferentes { get; set; }

        Des des = new Des();

        public TriploDes(string chaves)
        {
            SeparaChaves(chaves); // Divide a chave de 48 caracters hexadecimais em 3 chaves de 16 caracteres hexadecimais
            Verifica();
        }

        public byte[] DecriptacaoArquivo(byte[] C)
        {
            byte[] B = des.DecriptacaoBytes(C, Estaticos.ConvHexByte(Chave3));
            byte[] A = des.EncriptacaoBytes(B, Estaticos.ConvHexByte(Chave2));
            byte[] P = des.DecriptacaoBytes(A, Estaticos.ConvHexByte(Chave1));

            return Estaticos.ReorganizaBlocos(P); //Reorganiza os bytes no tamanho original
        }

        public byte[] EncriptacaoArquivo(byte[] P)
        {
            P = Estaticos.OrganizarBlocos(P, 8); //Organiza os bytes em múltiplos de 8 (múltiplos de 64 bits).

            byte[] A = des.EncriptacaoBytes(P, Estaticos.ConvHexByte(Chave1)); //Retorna os bytes Encriptados
            byte[] B = des.DecriptacaoBytes(A, Estaticos.ConvHexByte(Chave2)); //Retorna os bytes Decriptados
            byte[] C = des.EncriptacaoBytes(B, Estaticos.ConvHexByte(Chave3)); //Retorna os bytes Encriptados

            return C;
        }

        public string DecriptacaoTexto(string texto)
        {
            byte[] C = des.ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            C = Estaticos.DesCorrigeISO(C); //Desfaz a função "CorrigeISO"

            byte[] B = des.DecriptacaoBytes(C, Estaticos.ConvHexByte(Chave3));
            byte[] A = des.EncriptacaoBytes(B, Estaticos.ConvHexByte(Chave2));
            byte[] P = des.DecriptacaoBytes(A, Estaticos.ConvHexByte(Chave1));

            P = Estaticos.ReorganizaBlocos(P); //Reorganiza os bytes no tamanho original

            return des.ISO.GetString(P); //Converte os bytes em uma string
        }

        public string EncriptacaoTexto(string texto)
        {
            byte[] P = des.ISO.GetBytes(texto); //Converte o texto claro em um conjunto de bytes
            P = Estaticos.OrganizarBlocos(P, 8); //Organiza os bytes em múltiplos de 8 (múltiplos de 64 bits).

            byte[] A = des.EncriptacaoBytes(P, Estaticos.ConvHexByte(Chave1)); //Retorna os bytes Encriptados
            byte[] B = des.DecriptacaoBytes(A, Estaticos.ConvHexByte(Chave2)); //Retorna os bytes Decriptados
            byte[] C = des.EncriptacaoBytes(B, Estaticos.ConvHexByte(Chave3)); //Retorna os bytes Encriptados

            C = Estaticos.CorrigeISO(C); //Evita caracteres problemáticos da codificação ISO Latin-1

            return des.ISO.GetString(C); //Converte os bytes em uma string
        }

        private void Verifica()
        {
            if (Chave1 == Chave2 || Chave1 == Chave3 || Chave2 == Chave3) //As 3 chaves devem ser diferentes entre si
                Diferentes = false;
            else
                Diferentes = true;
        }

        private void SeparaChaves(string chaves) //Separa as 3 chaves
        {
            int tam = chaves.Length;

            for (int i = 0; i < (tam / 3); i++) //De 0 à 16
                Chave1 += chaves[i];

            for (int i = (tam / 3); i < ((tam * 2) / 3) ; i++) //De 16 à 32
                Chave2 += chaves[i];

            for (int i = ((tam * 2) / 3); i < tam; i++) //De 32 à 48
                Chave3 += chaves[i];
        }
    }
}
