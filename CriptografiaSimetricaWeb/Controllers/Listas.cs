using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CriptografiaSimetricaWeb.Controllers
{
    public class Listas
    {
        public string Valor { get; set; }
        public string Nome { get; set; }

        public static List<Listas> ListaAlgoritmos()
        {
            return new List<Listas>{
                new Listas() { Valor = "1", Nome = "DES"},
                new Listas() { Valor = "2", Nome = "3DES"},
                new Listas() { Valor = "3", Nome = "AES"},
                new Listas() { Valor = "4", Nome = "Blowfish"},
                new Listas() { Valor = "5", Nome = "Twofish"}
            };
        }

        public static List<Listas> ListaTipo()
        {
            return new List<Listas>{
                new Listas() { Valor = "1", Nome = "Encriptar"},
                new Listas() { Valor = "2", Nome = "Decriptar"}
            };
        }
    }
}