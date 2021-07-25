using CriptografiaSimetricaWeb.Algoritmos;
using CriptografiaSimetricaWeb.Models;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Windows.Forms;
using System.IO;

namespace CriptografiaSimetricaWeb.Controllers
{
    public class ArquivoController : Controller
    {
        private string chave { get; set; }
        private byte[] ArquivoTemp { get; set; }

        DbCriptografiaEntities db = new DbCriptografiaEntities();

        // GET: Arquivo
        public ActionResult Index()
        {
            ViewBag.Tipo = new SelectList(Listas.ListaTipo(), "Valor", "Nome");
            ViewBag.Algoritmo = new SelectList(Listas.ListaAlgoritmos(), "Valor", "Nome");

            return View();
        }

        [HttpPost]
        [ValidateInput(false)]
        public ActionResult Index(Parametros parametros)
        {
            ViewBag.Tipo = new SelectList(Listas.ListaTipo(), "Valor", "Nome", parametros.Tipo);
            ViewBag.Algoritmo = new SelectList(Listas.ListaAlgoritmos(), "Valor", "Nome", parametros.Algoritmo);

            try
            {
                if (!string.IsNullOrWhiteSpace(parametros.Chave))
                    chave = parametros.Chave.Replace(" ", "").Replace(":", "");

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
                else if (parametros.ArquivoPc.ContentLength == 0)
                {
                    ViewBag.Aviso = "Escolha algum arquivo";
                    ViewBag.Focus = "ArquivoPc";
                }
                else if (string.IsNullOrWhiteSpace(parametros.NomeArquivo))
                {
                    ViewBag.Aviso = "Digite um nome para o arquivo (Ex: nome.ext)";
                    ViewBag.Focus = "NomeArquivo";
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

                            ArquivoTemp = new byte[parametros.ArquivoPc.ContentLength];
                            parametros.ArquivoPc.InputStream.Read(ArquivoTemp, 0, parametros.ArquivoPc.ContentLength);

                            if (parametros.Tipo == 1)
                                ArquivoTemp = des.EncriptacaoArquivos(ArquivoTemp, chave);
                            else if (parametros.Tipo == 2)
                                ArquivoTemp = des.DecriptacaoArquivos(ArquivoTemp, chave);

                            return DownloadFile(parametros.NomeArquivo);
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
                                ArquivoTemp = new byte[parametros.ArquivoPc.ContentLength];
                                parametros.ArquivoPc.InputStream.Read(ArquivoTemp, 0, parametros.ArquivoPc.ContentLength);

                                if (parametros.Tipo == 1)
                                    ArquivoTemp = triploDes.EncriptacaoArquivo(ArquivoTemp);
                                else if (parametros.Tipo == 2)
                                    ArquivoTemp = triploDes.DecriptacaoArquivo(ArquivoTemp);

                                return DownloadFile(parametros.NomeArquivo);
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

                            ArquivoTemp = new byte[parametros.ArquivoPc.ContentLength];
                            parametros.ArquivoPc.InputStream.Read(ArquivoTemp, 0, parametros.ArquivoPc.ContentLength);

                            if (parametros.Tipo == 1)
                                ArquivoTemp = aes.EncriptacaoArquivos(ArquivoTemp, chave);
                            else if (parametros.Tipo == 2)
                                ArquivoTemp = aes.DecriptacaoArquivos(ArquivoTemp, chave);

                            return DownloadFile(parametros.NomeArquivo);
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

                            ArquivoTemp = new byte[parametros.ArquivoPc.ContentLength];
                            parametros.ArquivoPc.InputStream.Read(ArquivoTemp, 0, parametros.ArquivoPc.ContentLength);

                            if (parametros.Tipo == 1)
                                ArquivoTemp = blowfish.EncriptacaoArquivos(ArquivoTemp, chave);
                            else if (parametros.Tipo == 2)
                                ArquivoTemp = blowfish.DecriptacaoArquivos(ArquivoTemp, chave);

                            return DownloadFile(parametros.NomeArquivo);
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

                            ArquivoTemp = new byte[parametros.ArquivoPc.ContentLength];
                            parametros.ArquivoPc.InputStream.Read(ArquivoTemp, 0, parametros.ArquivoPc.ContentLength);

                            if (parametros.Tipo == 1)
                                ArquivoTemp = twofish.EncriptacaoArquivos(ArquivoTemp, chave);
                            else if (parametros.Tipo == 2)
                                ArquivoTemp = twofish.DecriptacaoArquivos(ArquivoTemp, chave);

                            return DownloadFile(parametros.NomeArquivo);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ViewBag.Aviso = ex.ToString();
            }
            
            return View(parametros);
        }

        private FileResult DownloadFile(string nomeArquivo)
        {
            return File(ArquivoTemp, System.Net.Mime.MediaTypeNames.Application.Octet, nomeArquivo);
        }

        public ActionResult Resultado()
        {
            Parametros parametros = new Parametros();
            parametros.TextoSaida = db.Temporario.First().Texto;

            return View(parametros);
        }

        private void Adicionar(string textoSaida)
        {
            if (db.Temporario.ToList().Count > 0)
            {
                var temporario = db.Temporario.First();

                temporario.Texto = textoSaida;
                db.Entry(temporario).State = EntityState.Modified;
                db.SaveChanges();
            }
            else
            {
                var temporario = new Temporario() { Texto = textoSaida };

                db.Temporario.Add(temporario);
                db.SaveChanges();
            }
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
