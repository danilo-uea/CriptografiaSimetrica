using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CriptografiaSimetricaWeb
{
    public static class ArrayExt
    {
        public static T[] GetRow<T>(this T[,] array, int row) //Obtém uma linha completa do array 2D
        {
            int cols = array.GetUpperBound(1) + 1;
            T[] result = new T[cols];

            int size = Marshal.SizeOf<T>();

            Buffer.BlockCopy(array, row * cols * size, result, 0, cols * size);

            return result;
        }
    }
}
