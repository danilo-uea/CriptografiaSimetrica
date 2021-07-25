using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace CriptografiaSimetricaWeb.Controllers
{
    public class ArquivoController : Controller
    {
        // GET: Arquivo
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(string TextoClaro, string Chave)
        {


            return View();
        }
    }
}
