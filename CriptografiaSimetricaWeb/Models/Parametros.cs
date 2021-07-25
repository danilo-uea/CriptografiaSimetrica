using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace CriptografiaSimetricaWeb.Models
{
    public class Parametros
    {
        public int? Algoritmo { get; set; }
        public int? Tipo { get; set; }
        public string Chave { get; set; }
        [DataType(DataType.MultilineText)]
        [Display(Name = "Texto Entrada")]
        public string TextoEntrada { get; set; }
        [DataType(DataType.MultilineText)]
        [Display(Name = "Texto Saída")]
        public string TextoSaida { get; set; }
    }
}