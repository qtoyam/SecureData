
//using System.Runtime.InteropServices;
//using System.Security.Cryptography;

//using BenchmarkDotNet.Attributes;

//using SecureData.Cryptography.Aes;

//namespace SecureData.Crypt.Benchmarks
//{
//	[MemoryDiagnoser]
//	//[ReturnValueValidator(true)]
//	[BenchmarkDotNet.Diagnostics.Windows.Configs.NativeMemoryProfiler]
//	[Orderer(BenchmarkDotNet.Order.SummaryOrderPolicy.FastestToSlowest)]
//	public class AesImplementations
//	{
//#nullable disable
//		private Aes256Ctr _myAesDef;
//		private Aes256Ctr _myAesT;
//		private Aes256Ctr _myAesNi;
//		private ICryptoTransform _cryptoTransform;
//		const int s = 1024 * 1024;
//		const int ctr = 0;
//		private byte[] Pt, Ct;
//		private byte[] Pt_copy;

//		[GlobalSetup]
//		public void GlobalSetup()
//		{
//			Random r = new(42);
//			byte[] iv = new byte[16];
//			byte[] key = new byte[32];
//			Pt = new byte[s];
//			Ct = new byte[s];
//			Pt_copy = new byte[s];
//			r.NextBytes(iv);
//			r.NextBytes(key);
//			r.NextBytes(Pt);
//			Pt.CopyTo(Pt_copy.AsSpan());
//			using (var aes = Aes.Create())
//			{
//				aes.Mode = CipherMode.ECB;
//				aes.Padding = PaddingMode.None;
//				aes.KeySize = 256;
//				aes.BlockSize = 128;
//				_cryptoTransform = aes.CreateEncryptor(key, null);
//			}
//			//_myAesDef = Aes256Ctr.Create(AesImplementation.Def);
//			_myAesDef.SetKeyIV(key, iv);

//			_myAesT = Aes256Ctr.Create(AesImplementation.T);
//			_myAesT.SetKeyIV(key, iv);

//			//_myAesNi = Aes256Ctr.Create(AesImplementation.NI);
//			_myAesNi.SetKeyIV(key, iv);
//		}
//		[GlobalCleanup]
//		public void GlobalCleanup()
//		{
//			_myAesDef?.Dispose();
//			_myAesT?.Dispose();
//			_myAesNi?.Dispose();
//			_cryptoTransform?.Dispose();
//			if (!Pt.SequenceEqual(Pt_copy))
//			{
//				throw new Exception("Pt changed.");
//			}
//		}

//		[Benchmark(Baseline = true)]
//		public void Aes_CryptoTransform()
//		{
//			_cryptoTransform.TransformBlock(Pt, 0, s, Ct, 0);
//		}

//		[Benchmark]
//		public void Aes_CtrDef()
//		{
//			_myAesDef.Transform(Pt, Ct, ctr);
//		}

//		[Benchmark]
//		public void Aes_CtrT()
//		{
//			_myAesT.Transform(Pt, Ct, ctr);
//		}

//		[Benchmark]
//		public void Aes_CtrNi()
//		{
//			_myAesNi.Transform(Pt, Ct, ctr);
//		}
//	}
//}