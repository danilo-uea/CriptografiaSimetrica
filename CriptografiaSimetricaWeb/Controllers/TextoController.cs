using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using CriptografiaSimetricaWeb.Models;
using CriptografiaSimetricaWeb.Algoritmos;

namespace CriptografiaSimetricaWeb.Controllers
{
    public class TextoController : Controller
    {
        private string chave { get; set; }

        // GET: Texto
        public ActionResult Index()
        {
            ViewBag.Tipo = new SelectList(Listas.ListaTipo(), "Valor", "Nome");
            ViewBag.Algoritmo = new SelectList(Listas.ListaAlgoritmos(), "Valor", "Nome");

            //Parametros param = new Parametros();
            //param.TextoSaida = "";

            return View();
        }

        public ActionResult Resultado(string Resultado)
        {
            //ViewBag.Tipo = new SelectList(Listas.ListaTipo(), "Valor", "Nome", parametros.Tipo);
            //ViewBag.Algoritmo = new SelectList(Listas.ListaAlgoritmos(), "Valor", "Nome", parametros.Algoritmo);

            Parametros parametros = new Parametros();
            parametros.TextoSaida = Resultado;

            return View(parametros);
        }

        [HttpPost]
        public ActionResult Index(Parametros parametros)
        {
            ViewBag.Tipo = new SelectList(Listas.ListaTipo(), "Valor", "Nome", parametros.Tipo);
            ViewBag.Algoritmo = new SelectList(Listas.ListaAlgoritmos(), "Valor", "Nome", parametros.Algoritmo);


            if (!string.IsNullOrWhiteSpace(parametros.Chave))
                chave = parametros.Chave.Replace(" ", "").Replace(":", "");

            parametros.TextoSaida = "";
            ViewBag.TextoSaida = "";


            if (parametros.Algoritmo == null)
            {
                ViewBag.Aviso = "Selecione o algoritmo de criptografia";
                ViewBag.Focus = "Algoritmo";
            }
            else if (parametros.Tipo == null)
            {
                ViewBag.Aviso = "Selecione o tipo de criptografia";
                ViewBag.Focus = "Tipo";
            }
            else if (string.IsNullOrWhiteSpace(chave))
            {
                ViewBag.Aviso = "Digite a chave";
                ViewBag.Focus = "Chave";
            }
            else if (!IsHex(chave))
            {
                ViewBag.Aviso = "Chave invalida! A chave deve estar em hexadecimal";
                ViewBag.Focus = "Chave";
            }
            else if (string.IsNullOrWhiteSpace(parametros.TextoEntrada))
            {
                ViewBag.Aviso = "Digite algum texto";
                ViewBag.Focus = "TextoEntrada";
            }
            else
            {
                if (parametros.Algoritmo == 1) //Algoritmo DES
                {
                    if (chave.Length != 16)
                    {
                        ViewBag.Aviso = "A chave deve ter 16 valores hexadecimais";
                        ViewBag.Focus = "Chave";
                    }
                    else
                    {
                        Des des = new Des();

                        if (parametros.Tipo == 1)
                            parametros.TextoSaida = des.EncriptacaoTexto(parametros.TextoEntrada, chave);
                        else if (parametros.Tipo == 2)
                            parametros.TextoSaida = des.DecriptacaoTexto(parametros.TextoEntrada, chave);

                        return RedirectToAction("Resultado", new { Resultado = parametros.TextoSaida });
                    }
                }
                else if (parametros.Algoritmo == 2) //Algoritmo 3DES
                {
                    if (chave.Length != 48)
                    {
                        ViewBag.Aviso = "Digite 48 hexadecimais (Três chaves tipo DES).";
                        ViewBag.Focus = "Chave";
                    }
                    else
                    {
                        TriploDes triploDes = new TriploDes(chave);

                        if (!triploDes.Diferentes) //Se as chaves não forem diferentes entre si
                        {
                            ViewBag.Aviso = "As 3 chaves devem ser diferentes entre si";
                            ViewBag.Focus = "Chave";
                        }
                        else
                        {
                            if (parametros.Tipo == 1)
                                parametros.TextoSaida = triploDes.EncriptacaoTexto(parametros.TextoEntrada);
                            else if (parametros.Tipo == 2)
                                parametros.TextoSaida = triploDes.DecriptacaoTexto(parametros.TextoEntrada);

                            return RedirectToAction("Resultado", new { Resultado = parametros.TextoSaida });
                        }
                    }
                }
                else if (parametros.Algoritmo == 3) //Algoritmo AES
                {
                    if (chave.Length != 32)
                    {
                        ViewBag.Aviso = "Digite 32 hexadecimais na chave do AES";
                        ViewBag.Focus = "Chave";
                    }
                    else
                    {
                        Aes aes = new Aes();

                        if (parametros.Tipo == 1)
                            parametros.TextoSaida = aes.EncriptacaoTexto(parametros.TextoEntrada, chave);
                        else if (parametros.Tipo == 2)
                            parametros.TextoSaida = aes.DecriptacaoTexto(parametros.TextoEntrada, chave);

                        return RedirectToAction("Resultado", new { Resultado = parametros.TextoSaida });
                    }
                }
                else if (parametros.Algoritmo == 4) //Algoritmo Blowfish
                {
                    if (chave.Length < 8 || chave.Length > 112)
                    {
                        ViewBag.Aviso = "Chave Blowfish, deve ser de 8 - 112 caracteres em hexadecimal";
                        ViewBag.Focus = "Chave";
                    }
                    else
                    {
                        Blowfish blowfish = new Blowfish();

                        if (parametros.Tipo == 1)
                            parametros.TextoSaida = blowfish.EncriptacaoTexto(parametros.TextoEntrada, chave);
                        else if (parametros.Tipo == 2)
                            parametros.TextoSaida = blowfish.DecriptacaoTexto(parametros.TextoEntrada, chave);

                        return RedirectToAction("Resultado", new { Resultado = parametros.TextoSaida });
                    }
                }
                else if (parametros.Algoritmo == 5) //Algoritmo Twofish
                {
                    if (chave.Length != 32)
                    {
                        ViewBag.Aviso = "A chave Twofish deve ter 32 caracteres em hexadecimal";
                        ViewBag.Focus = "Chave";
                    }
                    else
                    {
                        Twofish twofish = new Twofish();

                        if (parametros.Tipo == 1)
                            parametros.TextoSaida = twofish.EncriptacaoTexto(parametros.TextoEntrada, chave);
                        else if (parametros.Tipo == 2)
                            parametros.TextoSaida = twofish.DecriptacaoTexto(parametros.TextoEntrada, chave);

                        return RedirectToAction("Resultado", new { Resultado = parametros.TextoSaida });
                    }
                }
            }

            return View(parametros);
        }

        private bool IsHex(string chave) //Verifica se a string só contém valores em hexadecimal
        {
            bool isHex;

            foreach (var c in chave)
            {
                isHex = ((c >= '0' && c <= '9') ||
                         (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F'));

                if (!isHex)
                    return false;
            }

            return true;
        }
    }
}