using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CriptografiaSimetricaWeb
{
    static class Estaticos
    {
        public static void ImprimeEstado(byte[,] estado)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write("{0} ", Convert.ToString(estado[i,j], 16).PadLeft(2, '0'));
                }
                Console.WriteLine();
            }

            Console.WriteLine();
        }

        public static byte[] DesCorrigeISO(byte[] texto) //Desfaz o processo da função: CorrigeISO
        {
            List<byte> bytes = new List<byte>(); //Lista de bytes
            int prox, tam = texto.Length; //O tamanho de bytes do texto

            for (int i = 0; i < tam; i++)
            {
                prox = i + 1; //Próximo valor no array de bytes

                if (texto[i] == 254 && (i != tam - 1)) //Se tiver valor 254 e não for o último
                {
                    if (texto[prox] != 254) //Se o próximo valor for diferente de 254
                        bytes.Add(Convert.ToByte(texto[prox] - 88));
                    else //Se o próximo valor for igual à 254
                        bytes.Add(texto[prox]);

                    i++;
                }
                else if (texto[i] == 255 && (i != tam - 1)) //Se tiver valor 255 e não for o último
                {
                    if (texto[prox] != 255) //Se o próximo valor for diferente de 255
                        bytes.Add(Convert.ToByte(texto[prox] + 39));
                    else //Se o próximo valor for igual à 255
                        bytes.Add(texto[prox]);

                    i++;
                }
                else
                    bytes.Add(texto[i]);
            }

            return bytes.ToArray();
        }

        public static byte[] CorrigeISO(byte[] texto) //Evita o uso de caracteres problemáticos da codificação ISO (Latin-1)
        {
            /*
             -Caracteres problemáticos:
	            -Grupo 01 [0   -  32]
	            -Grupo 02 [127 - 160]
            -Começar do valor 88[X] até o 122[z] para os dois grupos
            -Representantes:
	            G1 = 254[þ] - 11111110
	            G2 = 255[ÿ] - 11111111
            -Exemplo:   '⌂' = 'ÿX'
                      [127] = [255][88]
             */

            List<byte> bytes = new List<byte>(); //Lista de bytes


            foreach (var item in texto)
            {
                if (item >= 0 && item <= 32)
                {
                    bytes.Add(Convert.ToByte(254));
                    bytes.Add(Convert.ToByte(88 + item));
                }
                else if (item >= 127 && item <= 160)
                {
                    bytes.Add(Convert.ToByte(255));
                    bytes.Add(Convert.ToByte(item - 39));
                }
                else if (item == 254 || item == 255)
                {
                    bytes.Add(item);
                    bytes.Add(item);
                }
                else
                    bytes.Add(item);
            }

            return bytes.ToArray();
        }

        public static byte[] ConvHexByte(string texto) //Converte uma string de hexadecimal em um array de bytes
        {
            texto = texto.Replace(" ", "").Replace(":", ""); //Refazer novamente por preucaução
            int tam = texto.Length; //Tamanho de caracteres hexadecimais
            byte[] bytes = new byte[tam / 2]; //O tamanho de bytes é a metade do tamanho de caracteres hexadecimal
            string hexa = "";

            for (int i = 0; i < tam; i++)
            {
                hexa += texto[i];

                if (i % 2 != 0) //Sempre que for número impar
                {
                    bytes[i / 2] = Convert.ToByte(hexa, 16); //Armazema os bytes
                    hexa = "";
                }
            }

            return bytes;
        }

        public static void OrganizaHexa(byte[] bytes, int quant) //Imprime os valores hexadecimais em formato de inteiro
        {
            int cont = 0;

            foreach (var b in bytes)
            {
                if (cont % quant == 0 && cont != 0)
                    Console.WriteLine();

                if (cont % quant == 0)
                    Console.Write("{ ");

                Console.Write("0x{0}, ", Convert.ToString(b, 16).ToUpper().PadLeft(2, '0'));

                if (cont % quant == quant -1)
                    Console.Write("},");

                cont++;
            }
        }

        public static byte[] OrganizarBlocos(byte[] dados, int m) //Organiza os bytes em multiplos de m (blocos de m bits)
        {
            int tam = dados.Length,
            tam_1 = tam + 1,         //É sempre adicionado por padrão um byte no início do array
            falta = m - (tam_1 % m), //Quanto falta para ser múltiplo de m bytes
            add = falta + 1,         //Quantos de bytes vai ser adicionado no total
            total = tam_1 + falta;   //Tamanho total de bytes a ser retornado

            byte[] retorno = new byte[total];
            retorno[0] = Convert.ToByte(add); //É sempre adicionado por padrão um byte no início do array, para armazenar a quantidade total de bytes adicionada.

            for (int i = 1; i < add; i++)
                retorno[i] = Convert.ToByte(0);

            for (int i = 0; i < tam; i++)
                retorno[i + add] = dados[i];

            return retorno;
        }

        public static byte[] ReorganizaBlocos(byte[] dados) //Reorganiza o tamanho dos bytes à quantidade original. Sem ser necessariamente múltiplo de m bytes
        {
            int tam = dados.Length, //Tamanho dos dados de entrada
            qtd = Convert.ToInt32(dados[0]), //Quantidade de bytes a ser retirados do início
            final = tam - qtd; //Tamanho do array de bytes a ser retornado

            byte[] retorno = new byte[final];

            for (int i = 0; i < final; i++)
                retorno[i] = dados[i + qtd];

            return retorno;
        }
    }
}
