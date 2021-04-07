using System;
using System.IO;
using System.Net;
using System.Text;
using System.IO.Compression;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Streams
{
	public static class StreamsExtension
	{
		/// <summary>
		/// Implements the logic of byte copying the contents of the source text file using class FileStream as a backing store stream.
		/// </summary>
		/// <param name="sourcePath">Path to source file.</param>
		/// <param name="destinationPath">Path to destination file.</param>
		/// <returns>The number of recorded bytes.</returns>
		/// <exception cref="ArgumentException">Throw if path to source file or path to destination file is null or empty.</exception>
		/// <exception cref="FileNotFoundException">Throw if source file doesn't exist.</exception>
		public static int ByteCopyWithFileStream(string sourcePath, string destinationPath)
		{
			InputValidation(sourcePath, destinationPath);

			int recordedBytes = 0;

			using (FileStream destination = new FileStream(destinationPath, FileMode.OpenOrCreate))
			{
				using (FileStream source = new FileStream(sourcePath, FileMode.Open))
				{
					int temp;
					for (int i = 0; i < source.Length; i++)
					{
						temp = source.ReadByte();
						recordedBytes += temp;
						destination.WriteByte((byte)temp);
					}
				}
			}

			return recordedBytes;
		}

		/// <summary>
		/// Implements the logic of block copying the contents of the source text file using FileStream buffer.
		/// </summary>
		/// <param name="sourcePath">Path to source file.</param>
		/// <param name="destinationPath">Path to destination file.</param>
		/// <returns>The number of recorded bytes.</returns>
		/// <exception cref="ArgumentException">Throw if path to source file or path to destination file is null or empty.</exception>
		/// <exception cref="FileNotFoundException">Throw if source file doesn't exist.</exception>
		public static int BlockCopyWithFileStream(string sourcePath, string destinationPath)
		{
			InputValidation(sourcePath, destinationPath);

			string temp = null;
			int recordedBytes = 0;

			using (FileStream source = new FileStream(sourcePath, FileMode.Open))
			{
				byte[] block = new byte[source.Length];

				while (source.Read(block, 0, block.Length) > 0)
				{
					temp += Encoding.Default.GetString(block);
				}
			}

			using (FileStream destination = new FileStream(destinationPath, FileMode.OpenOrCreate))
			{
				byte[] block = new UTF8Encoding(true).GetBytes(temp);
				destination.Write(block, 0, block.Length);

				foreach (byte b in block)
				{
					recordedBytes += b;
				}
			}

			return recordedBytes;
		}

		/// <summary>am.
		/// Implements the logic of block copying the contents of the source text file using FileStream and class-decorator BufferedStre
		/// </summary>
		/// <param name="sourcePath">Path to source file.</param>
		/// <param name="destinationPath">Path to destination file.</param>
		/// <returns>The number of recorded bytes.</returns>
		/// <exception cref="ArgumentException">Throw if path to source file or path to destination file is null or empty.</exception>
		/// <exception cref="FileNotFoundException">Throw if source file doesn't exist.</exception>
		public static int BlockCopyWithBufferedStream(string sourcePath, string destinationPath)
		{
			InputValidation(sourcePath, destinationPath);

			int recordedBytes = 0;

			using FileStream source = new FileStream(sourcePath, FileMode.Open);
			using FileStream destination = new FileStream(destinationPath, FileMode.OpenOrCreate);
			using BufferedStream bufSource = new BufferedStream(source);

			for (int i = 0; i < bufSource.Length; i++)
			{
				int temp = bufSource.ReadByte();
				recordedBytes += temp;
				destination.WriteByte((byte)temp);
			}

			return recordedBytes;
		}

		/// <summary>
		/// Implements the logic of line-by-line copying of the contents of the source text file
		/// using FileStream and classes-adapters  StreamReader/StreamWriter
		/// </summary>
		/// <param name="sourcePath">Path to source file.</param>
		/// <param name="destinationPath">Path to destination file.</param>
		/// <returns>The number of recorded lines.</returns>
		/// <exception cref="ArgumentException">Throw if path to source file or path to destination file are null or empty.</exception>
		/// <exception cref="FileNotFoundException">Throw if source file doesn't exist.</exception>
		public static int LineCopy(string sourcePath, string destinationPath)
		{
			InputValidation(sourcePath, destinationPath);

			int counter = 0;
			string line;


			using StreamReader sr = new StreamReader(sourcePath);
			using StreamWriter sw = new StreamWriter(destinationPath, false);

			while ((line = sr.ReadLine()) != null)
			{
				counter++;
			}

			sr.BaseStream.Position = 0;

			for (int i = 0; i < counter; i++)
			{
				line = sr.ReadLine();

				if (i == counter - 1)
				{
					sw.Write(line);
					break;
				}

				sw.WriteLine(line);
			}

			return counter;
		}

		/// <summary>
		/// Reads file content encoded with non Unicode encoding.
		/// </summary>
		/// <param name="sourcePath">Path to source file.</param>
		/// <param name="encoding">Encoding name.</param>
		/// <returns>Unicoded file content.</returns>
		/// <exception cref="ArgumentException">Throw if path to source file or encoding string is null or empty.</exception>
		/// <exception cref="FileNotFoundException">Throw if source file doesn't exist.</exception>
		public static string ReadEncodedText(string sourcePath, string encoding)
		{
			InputValidation(sourcePath);

			using StreamReader sr = new StreamReader(sourcePath, Encoding.GetEncoding(encoding));

			string result = sr.ReadToEnd();

			return result;
		}

		/// <summary>
		/// Returns decompressed stream from file. 
		/// </summary>
		/// <param name="sourcePath">Path to source file.</param>
		/// <param name="method">Method used for compression (none, deflate, gzip).</param>
		/// <returns>Output stream.</returns>
		/// <exception cref="ArgumentException">Throw if path to source file is null or empty.</exception>
		/// <exception cref="FileNotFoundException">Throw if source file doesn't exist.</exception>
		public static Stream DecompressStream(string sourcePath, DecompressionMethods method)
		{
			InputValidation(sourcePath);

			Stream stream = null;
			FileStream fileStream = new FileStream(sourcePath, FileMode.Open);
			switch (method)
			{
				case DecompressionMethods.None:
					stream = fileStream;
					break;

				case DecompressionMethods.Deflate:
					DeflateStream defStream = new DeflateStream(fileStream, CompressionMode.Decompress);
					stream = defStream;
					break;

				case DecompressionMethods.GZip:
					GZipStream gZipStream = new GZipStream(fileStream, CompressionMode.Decompress);
					stream = gZipStream;
					break;
			}

			return stream;
		}

		/// <summary>
		/// Calculates hash of stream using specified algorithm.
		/// </summary>
		/// <param name="stream">Source stream.</param>
		/// <param name="hashAlgorithmName">
		///     Hash algorithm ("MD5","SHA1","SHA256" and other supported by .NET).
		/// </param>
		/// <returns>Hash.</returns>
		public static string CalculateHash(this Stream stream, string hashAlgorithmName)
		{
			byte[] hash = null;

			if (hashAlgorithmName == "MD5" || hashAlgorithmName == "System.Security.Cryptography.MD5")
			{
				using (var md5 = MD5.Create())
				{
					hash = md5.ComputeHash(stream);
				}
			}
			else if (hashAlgorithmName == "SHA" || hashAlgorithmName == "SHA1" || hashAlgorithmName == "System.Security.Cryptography.SHA1")
			{
				using (var sha = SHA1.Create())
				{
					hash = sha.ComputeHash(stream);
				}
			}
			else if (hashAlgorithmName == "SHA256" || hashAlgorithmName == "SHA-256" || hashAlgorithmName == "System.Security.Cryptography.SHA256")
			{
				using (var sha256 = SHA256.Create())
				{
					hash = sha256.ComputeHash(stream);
				}
			}
			else if (hashAlgorithmName == "SHA384" || hashAlgorithmName == "SHA-384" || hashAlgorithmName == "System.Security.Cryptography.SHA384")
			{
				using (var sha384 = SHA384.Create())
				{
					hash = sha384.ComputeHash(stream);
				}
			}
			else if (hashAlgorithmName == "SHA512" || hashAlgorithmName == "SHA-512" || hashAlgorithmName == "System.Security.Cryptography.SHA512")
			{
				using (var sha512 = SHA512.Create())
				{
					hash = sha512.ComputeHash(stream);
				}
			}
			else
			{
				throw new ArgumentException();
			}

			var sBuilder = new StringBuilder();

			for (int i = 0; i < hash.Length; i++)
			{
				sBuilder.Append(hash[i].ToString("x2"));
			}

			return sBuilder.ToString().ToUpper();
		}




		private static void InputValidation(string sourcePath, string destinationPath)
		{
			if (string.IsNullOrWhiteSpace(sourcePath))
			{
				throw new ArgumentException($"{nameof(sourcePath)} cannot be null or empty or whitespace.", nameof(sourcePath));
			}

			if (!File.Exists(sourcePath))
			{
				throw new FileNotFoundException($"File '{sourcePath}' not found. Parameter name: {nameof(sourcePath)}.");
			}

			if (string.IsNullOrWhiteSpace(destinationPath))
			{
				throw new ArgumentException($"{nameof(destinationPath)} cannot be null or empty or whitespace",
					nameof(destinationPath));
			}
		}

		private static void InputValidation(string sourcePath)
		{
			if (string.IsNullOrWhiteSpace(sourcePath))
			{
				throw new ArgumentException($"{nameof(sourcePath)} cannot be null or empty or whitespace.", nameof(sourcePath));
			}

			if (!File.Exists(sourcePath))
			{
				throw new FileNotFoundException($"File '{sourcePath}' not found. Parameter name: {nameof(sourcePath)}.");
			}
		}
	}
}