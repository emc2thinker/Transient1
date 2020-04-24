using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

using Dexcom.Common;
using Dexcom.Common.AppCompatibility;
using Dexcom.Common.Legal;
using Dexcom.Common.Share;
using Thinktecture.IdentityModel.Client;
using System.ServiceModel.Web;
using System.Xml;
using System.ServiceModel;
using Dexcom.Common.Share.Events;
using System.Threading;
using System.Threading.Tasks;
using Dexcom.Common.Data;
using Dexcom.Common.Share.DataSync;

namespace Dexcom.Testing.ShareTests
{
	[TestFixture]
	public class ShareSmokeTest
	{
		public SynchronizedCollection<string> Exceptions { get; set; }

		public SynchronizedCollection<string> Messages { get; set; }

		public SynchronizedCollection<double> ExecutionTimes { get; set; }

		public int CallRetryCount { get; set; } = 1;

		public int RetriesPerformed { get; set; }

		public int MaxRetriesExceeded { get; set; }

		#region Setup/TearDown

		[OneTimeSetUp]
		public static void ClassSetup()
		{
		}

		#endregion

		public static Dictionary<string, object> DeviceSettingsRecords = new Dictionary<string, object>()
		{
			{"RecordedSystemTime", "2016-10-20T20:20:20.020Z"},
			{"RecordedDisplayTime", "2016-10-21T21:21:21.021-21:00"},
			{"Language", "en-US"},
			{"IsMmolDisplayMode", false},
			{"Is24HourMode", false},
			{"IsBlindedMode", false},
			{"TransmitterId", "TEST_TXID"},
			{"SystemTimeOffset", 11},
			{"DisplayTimeOffset", 12},
			{"SoftwareNumber", "SW0TEST"},
			{"SoftwareVersion", "10.0.0"},
			{"SenderInformation","{\"ProductName\": \"Dexcom SMOKE TEST\",\"SoftwareNumber\": \"SW0TEST\",\"SoftwareVersion\": \"10.0.0.0\",\"HostOperatingSystemVersion\": \"Microsoft Windows NT 6.2.9200.0\",\"LocalComputerTime\": \"2016-10-24T13:41:10.9163773-05:00\",\"LocalComputerOffsetToUtc\": \"00:00:00\",\"WasAbleToDetermineLocalOffset\": false,\"ReceiverSystemTime\": \"2016-10-24T15:41:14\"}" }
		};

		public static DataPost CreateSmokeDataPost(Guid patientId)
		{
			string json_device_settings_record = "";

			var json_post_header =
				"{" +
					$"\"PatientId\": \"{(patientId)}\"," +
					$"\"SourceStream\": \"Receiver\"," +
					$"\"SequenceNumber\": {CommonTools.ConvertToPosixTime(DateTime.UtcNow)}," +
					"\"TransmitterNumber\": \"TEST_TXID\"," +
					"\"ReceiverNumber\": \"TEST_RXID\"," +
					"\"Tag\": \"\"," +
				"}";
			var post_header = DataSyncUtils.FromJsonString<DataPostHeader>(json_post_header);
			var patient_id = post_header.PatientId;

			var public_data_manifest = new DataPostManifest();
			var public_data_content = new DataPostContent();
			var private_data_manifest = new DataPostManifest();
			var private_data_content = new DataPostContent();

			#region Public Records

			{
				var device_settings_records_list = new List<DeviceSettingsRecord>();

				json_device_settings_record =
					"{" +
					"\"RecordedSystemTime\":\"" + DeviceSettingsRecords["RecordedSystemTime"] + "\"," +
					"\"RecordedDisplayTime\":\"" + DeviceSettingsRecords["RecordedDisplayTime"] + "\"," +
					"\"Language\":\"" + DeviceSettingsRecords["Language"] + "\"," +
					"\"IsMmolDisplayMode\":\"" + DeviceSettingsRecords["IsMmolDisplayMode"] + "\"," +
					"\"Is24HourMode\":\"" + DeviceSettingsRecords["Is24HourMode"] + "\"," +
					"\"IsBlindedMode\":\"" + DeviceSettingsRecords["IsBlindedMode"] + "\"," +
					"\"TransmitterId\":\"" + DeviceSettingsRecords["TransmitterId"] + "\"," +
					"\"SystemTimeOffset\":\"" + DeviceSettingsRecords["SystemTimeOffset"] + "\"," +
					"\"DisplayTimeOffset\":\"" + DeviceSettingsRecords["DisplayTimeOffset"] + "\"," +
					"\"SoftwareNumber\":\"" + DeviceSettingsRecords["SoftwareNumber"] + "\"," +
					"\"SoftwareVersion\":\"" + DeviceSettingsRecords["SoftwareVersion"] + "\"," +
					"\"SenderInformation\":" + DeviceSettingsRecords["SenderInformation"] +
					"}";

				device_settings_records_list.Add(DataSyncUtils.FromJsonString<DeviceSettingsRecord>(json_device_settings_record));
				var device_settings_prep = DataSyncUtils.CreateRecordsEntry(device_settings_records_list);
				public_data_manifest.Entries.Add(device_settings_prep.Item1);

				public_data_content.Entries.Add(device_settings_prep.Item2);
			}

			#endregion Public Records

			#region Private Records
			#endregion Private Records

			var post = new DataPost
			{
				//PostId = postId,
				//PostedTimestamp = DateTimeOffset.Parse("2016-11-03T07:39:47.1234567-07:00")
				PostHeader = DataSyncUtils.CreateJsonDataContainerForPatientStuff(post_header, patient_id, zipIt: false),
				PublicDataManifest = DataSyncUtils.CreateJsonDataContainerForPatientStuff(public_data_manifest, patient_id, zipIt: false),
				PublicDataContent = DataSyncUtils.CreateJsonDataContainerForPatientStuff(public_data_content, patient_id, zipIt: false),
				PrivateDataManifest = DataSyncUtils.CreateJsonDataContainerForPatientStuff(private_data_manifest, patient_id, zipIt: false),
				PrivateDataContent = DataSyncUtils.CreateJsonDataContainerForPatientStuff(private_data_content, patient_id, zipIt: false),
			};

			return post;
		}

		public ShareSmokeTest()
		{
			Initialize();
		}

		public void Initialize()
		{
			Exceptions = new SynchronizedCollection<string>();
			ExecutionTimes = new SynchronizedCollection<double>();
			Messages = new SynchronizedCollection<string>();
		}

		private T DoCallFunction<T>(Func<T> function, string msg = null)
		{
			T result = default(T);
			PerformanceTimer timer = new PerformanceTimer();
			int retries = CallRetryCount;

			while (retries >= 0)
			{
				try
				{
					timer.Start();
					result = function();
					timer.Stop();
					ExecutionTimes.Add(timer.GetElapsedTime());
					if (msg != null) Messages.Add(msg);
					break;
				}
				catch (Exception exception)
				{
					timer.Stop();
					ExecutionTimes.Add(timer.GetElapsedTime());
					timer.Reset();

					retries--;
					RetriesPerformed++;
					var error_msg = DoProcessException(exception);
					Messages.Add($"Failed during function: retries={retries}: function=\"{msg ?? "unknown"}\" : Error=\"{error_msg}\"");

					Thread.Sleep(1000); // Backoff a bit and try again.
				}
			}

			if (retries < 0)
			{
				MaxRetriesExceeded++;
				throw new DexComException("Max retries exceeded in simulated worker.");
			}

			if ((ExecutionTimes.Count % 1000) == 0)
			{
                // FORNOW ExecutionTimes.TrimExcess();
			}

            return result;
		}

		private void DoCallAction(Action action, string msg = null)
		{
			PerformanceTimer timer = new PerformanceTimer();
			int retries = CallRetryCount;

			while (retries >= 0)
			{
				try
				{
					timer.Start();
					action();
					timer.Stop();
					ExecutionTimes.Add(timer.GetElapsedTime());
					if (msg != null) Messages.Add(msg);
					break;
				}
				catch (Exception exception)
				{
					timer.Stop();
					ExecutionTimes.Add(timer.GetElapsedTime());
					timer.Reset();

					retries--;
					RetriesPerformed++;
					var error_msg = DoProcessException(exception);
					Messages.Add($"Failed during action: retries remaining ={retries+1}: action=\"{msg ?? "unknown"}\" : Error=\"{error_msg}\"");

					Thread.Sleep(1000); // Backoff a bit and try again.
				}
			}

			if (retries < 0)
			{
				MaxRetriesExceeded++;
				throw new DexComException("Max retries exceeded in simulated worker.");
			}

			if ((ExecutionTimes.Count % 1000) == 0)
			{
				// FORNOW ExecutionTimes.TrimExcess();
			}
		}

		private string DoProcessException(Exception exception)
		{
			string result = string.Empty;

			if (exception is WebFaultException<WebServiceException>)
			{
				WebFaultException<WebServiceException> fault_exception = exception as WebFaultException<WebServiceException>;
				result += fault_exception.Detail.ToString() + Environment.NewLine;
				result += ("Code = " + fault_exception.Detail.Code ?? string.Empty) + Environment.NewLine;
				result += ("Message = " + fault_exception.Detail.Message ?? string.Empty) + Environment.NewLine;
			}
			else if (exception is OnlineException)
			{
				result += exception.ToString();
			}
			else if (exception is FaultException)
			{
				FaultException fault_exception = exception as FaultException;
				string code = fault_exception.Code != null ? fault_exception.Code.Name : string.Empty;
				string sub_code = fault_exception.Code != null && fault_exception.Code.SubCode != null ? fault_exception.Code.SubCode.Name : string.Empty;

				XmlDocument x_doc = new XmlDocument();
				XmlElement x_error = x_doc.CreateElement("ERROR");
				x_error.SetAttribute("Type", exception.GetType().Name);
				x_error.SetAttribute("Code", code);
				x_error.SetAttribute("Message", fault_exception.Message);
				x_error.SetAttribute("SubCode", sub_code);

				result += x_error.OuterXml;
			}
			else
			{
				XmlDocument x_doc = new XmlDocument();
				XmlElement x_error = x_doc.CreateElement("ERROR");
				x_error.SetAttribute("Type", exception.GetType().Name);
				x_error.SetAttribute("Code", "");
				x_error.SetAttribute("Message", exception.Message);
				x_error.SetAttribute("SubCode", "");

				result += x_error.OuterXml;
			}

			Exceptions.Add(result);

			return result;
		}

        private void DoDumpResultToConsole()
        {
            Console.WriteLine();
            if (ExecutionTimes.Any())
            {
                List<int> quantiles = new List<int>(new int[] { 0, 2500, 5000, 7500, 9500, 9800, 9900, 9950, 9990, 9995, 10000 });
                var percentiles = MathUtils.Quantile(ExecutionTimes.ToList(), quantiles, 10000);

                var stats = $"Execution Times Percentiles (milliseconds) for {ExecutionTimes.Count} time points:\r\n";
                if (percentiles.Count == quantiles.Count)
                {
                    for (int count = 0; count < percentiles.Count; count++)
                    {
                        stats += string.Format("{0:0.00}%={1:000} \r\n", ((double)quantiles[count]) / 100.0, percentiles[count]);
                    }
                }
                Console.WriteLine(stats);
            }

            Console.WriteLine();
            Console.WriteLine($"MESSAGES ... Count = {Messages.Count}");
            foreach (var msg in Messages)
            {
                Console.WriteLine(msg);
            }

            Console.WriteLine();
            Console.WriteLine($"ERRORS ... Count = {Exceptions.Count}, Retry Attempts/Exceeded = {RetriesPerformed}/{MaxRetriesExceeded}");
            foreach (var error in Exceptions)
            {
                Console.WriteLine(error);
            }

            Console.WriteLine();
            Console.WriteLine("Done!");
        }

#if DEBUG
        public const string SignedRequestXmlRsaPublicKey_PROD101 = "<RSAKeyValue><Modulus>hR1op97RL74ZPlwmTCz/gqJBmezl9XnEd9+qGtBadd9GP8yxTvhxysxS35Hs0vdRty7/uvOiG26Bmy2NAsUwxaaTy9Jf7Knceg4Zb5HpxcZR7Oku7RBuP9wTqDvLw/DLWIpq/n3norwwfZ5kQtB2Q6n/WN6DS6dkJvWozXJS1moBoN66znX3jJDMaq8KSW6xOg1tBPoA7ki3Kgb/NeO8xspYhWtjuC7HHxI5O+1elaGgs+Bb5qB2ctKqs909gtcrH62Vo+CdeMVdOHlluaTPTwudnaVu5zSu0ubcMyca0I4O8IloPJT3buExc2iP4uZtN3lfpjft7PGXAp95QMS41w==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
#endif
		/// <summary>
		/// Can't be used for decryption, only for creating signed requests during testing or client side code!
		/// </summary>
		/// <param name="keyIndex"></param>
		/// <returns></returns>
		public static RSACryptoServiceProvider LookupWellKnownPublicOnlyDeviceKeyRsaWrapper(int keyIndex)
		{
			RSACryptoServiceProvider wrapper_key = null;
#if DEBUG
			if (keyIndex == -1 || keyIndex == 1) // Content AES key encrypted with TEST RSA key
			{
				wrapper_key = new RSACryptoServiceProvider(EventsDataUtils.RsaKeySize);
				wrapper_key.FromXmlString(EventsDataUtils.SignedRequestXmlRsaPublicKey_TEST1);
			}
			else if (keyIndex == 101)
			{
				wrapper_key = new RSACryptoServiceProvider(EventsDataUtils.RsaKeySize);
				wrapper_key.FromXmlString(SignedRequestXmlRsaPublicKey_PROD101);
			}
#endif

			return wrapper_key;
		}

		private string DoRegisterDeviceKey(IShareWebServices service, Guid appId, Guid accountId, string deviceKey, int rsaKey, string password, bool isPublisher)
		{
			// On the fly, generate our device secret from account + device key.
			var device_secret = EventsDataUtils.GenerateAccountDeviceKeySignatureAndSecret(accountId, deviceKey).Item2;

			// Register our (new) device key.
			DeviceKeyRequest request = new DeviceKeyRequest();
			request.AppId = appId;
			request.Password = password;
			request.RequestId = Guid.NewGuid();
			request.Timestamp = TimeManager.DateTimeOffsetNow;
			request.Key = deviceKey;
			request.KeyHmac = request.Key.HmacSignature(accountId.ToString("D") + request.Key, isTruncated: true, isBase64UrlEncoded: true);

			var register_key_header = new RequestHeader() { AccountId = accountId, ApplicationId = appId, Timestamp = DateTimeOffset.Now, IsPayloadZipped = false };
			var register_key_payload = new DeviceKeyRequestPayload() { KeyRequest = request, };
			register_key_header.EncryptionKey = new EncryptionKey() { RsaKey = rsaKey };
			var register_key_signed_request = EventsDataUtils.CreateSignedRequest(register_key_header, register_key_payload, device_secret, LookupWellKnownPublicOnlyDeviceKeyRsaWrapper);

			if (isPublisher)
			{
				DoCallFunction(() => service.RegisterPublisherDeviceKey(register_key_signed_request.RawRequest));
			}
			else
			{
				DoCallFunction(() => service.RegisterSubscriberDeviceKey(register_key_signed_request.RawRequest));
			}

			return device_secret;
		}

        private void DoTestSystemClockOffset(Func<ClockOffset> getClockOffset, string serviceCallName)
		{
			var hosts = new ConcurrentDictionary<string, int>();
			var delta_max = TimeSpan.FromSeconds(1);
			bool did_ever_connect = false;
            //for (int i = 0; i < 20; i++)
            Parallel.For(0, 20, (int index) =>
            {
                var clock_offset = DoCallFunction(getClockOffset);

                hosts.AddOrUpdate(clock_offset.Host, (key) => 1, (key, val) => val + 1);

                if (clock_offset.DidConnect)
                {
                    if (clock_offset.Offset.Duration() > TimeSpan.FromHours(1))
                    {
                        Exceptions.Add($"WARNING: {serviceCallName}: host={clock_offset.Host} returned time offset > 1 HOUR !? TimeZone SNTP Error!?, skipping and trying again.");
                    }
                    else
                    {
                        did_ever_connect = true;
                        if (clock_offset.Offset.Duration() >= delta_max)
                        {
                            Exceptions.Add($"WARNING: {serviceCallName}: ClockOffset {clock_offset.Offset} more than {delta_max} duration found for host {clock_offset.Host}!");
                        }
                    }
                }
            }
            ); // Comment out if not running parallel.

			foreach(var entry in hosts) Messages.Add($"{serviceCallName}: Connected to SystemClockOffset : Host = {entry.Key} @ {entry.Value} times.");

			if (did_ever_connect == false)
			{
				Exceptions.Add($"WARNING: {serviceCallName}: All calls to SystemClockOffset failed to get SNTP connection.");
			}
		}

		public XObject RunSmokeTest(ISmokeTestContext context)
		{
			string device_key = StringUtils.GenerateRandomString(10); // Simulate phone choosing a random device key.
			string smoke_patient_device_secret = string.Empty;
            Guid smoked_new_data_post_id = Guid.Empty;

            var share_service = WebServiceTools.MakeRestWebServiceClient<IShareWebServices>(context.ShareWebServices);
			var datapoast_service = WebServiceTools.MakeRestWebServiceClient<IShareDataPostWebServices>(context.ShareDataPostWebServices);
			var app_compat_service = WebServiceTools.MakeRestWebServiceClient<IAppCompatibilityWebService>(context.AppCompatibilityWebServices);
			var legal_service = WebServiceTools.MakeRestWebServiceClient<ILegalWebServices>(context.LegalWebServices);

			var share_admin_service = WebServiceTools.MakeRestWebServiceClient<IShareAdminWebServices>(context.ShareAdminWebServices);
			var app_compat_admin_service = WebServiceTools.MakeRestWebServiceClient<IAppCompatibilityAdminWebService>(context.AppCompatibilityAdminWebServices);
			var datasync_service = WebServiceTools.MakeRestWebServiceClient<IShareDataSyncWebServices>(context.ShareDataSyncWebServices);
			var share_uam_service = WebServiceTools.MakeRestWebServiceClient<IShareUAMWebServices>(context.ShareUAMWebServices);
			var admin_login_service = WebServiceTools.MakeRestWebServiceClient<ILoginWebServices>(context.ShareAdminWebServices_Login);
			var user_service = WebServiceTools.MakeRestWebServiceClient<IUserWebServices>(context.ShareAdminWebServices_User);

            // Warm up our client side connections to each service ... then start testing.
            share_service.Ping();
            datapoast_service.Ping();
            app_compat_service.Ping();
            legal_service.Ping();
            share_admin_service.Ping();
            app_compat_admin_service.Ping();
            datasync_service.Ping();
            share_uam_service.Ping();

            #region PING 'em
            DoCallAction(() => share_service.Ping(), "share_service.Ping");
			DoCallAction(() => datapoast_service.Ping(), "datapoast_service.Ping");
			DoCallAction(() => app_compat_service.Ping(), "app_compat_service.Ping");
			DoCallAction(() => legal_service.Ping(), "legal_service.Ping");
			DoCallAction(() => share_admin_service.Ping(), "share_admin_service.Ping");
			DoCallAction(() => app_compat_admin_service.Ping(), "app_compat_admin_service.Ping");
			DoCallAction(() => datasync_service.Ping(), "datasync_service.Ping");
			DoCallAction(() => share_uam_service.Ping(), "share_uam_service.Ping");
			#endregion PING 'em

			#region TRACE(DB) 'em
			DoCallAction(() => share_service.Trace(), "share_service.Trace");
			DoCallAction(() => datapoast_service.Trace(), "datapoast_service.Trace");
			DoCallAction(() => app_compat_service.Trace(), "app_compat_service.Trace");
			DoCallAction(() => legal_service.Trace(), "legal_service.Trace");
			DoCallAction(() => share_admin_service.Trace(), "share_admin_service.Trace");
			DoCallAction(() => app_compat_admin_service.Trace(), "app_compat_admin_service.Trace");
			DoCallAction(() => datasync_service.Trace(), "datasync_service.Trace");
			DoCallAction(() => share_uam_service.Trace(), "share_uam_service.Trace");
			#endregion TRACE(DB) 'em

			#region CHECK CLOCKS
			if (context.CheckClocks)
			{
				DoTestSystemClockOffset(() => share_service.SystemClockOffset(), "share_service");
				DoTestSystemClockOffset(() => datapoast_service.SystemClockOffset(), "datapoast_service");
				//DoTestSystemClockOffset(() => app_compat_service.SystemClockOffset(), "app_compat_service");
				DoTestSystemClockOffset(() => legal_service.SystemClockOffset(), "legal_service");
				DoTestSystemClockOffset(() => share_admin_service.SystemClockOffset(), "share_admin_service");
				DoTestSystemClockOffset(() => app_compat_admin_service.SystemClockOffset(), "app_compat_admin_service");
				DoTestSystemClockOffset(() => datasync_service.SystemClockOffset(), "datasync_service");
				DoTestSystemClockOffset(() => share_uam_service.SystemClockOffset(), "share_uam_service");
			}
			#endregion CHECK CLOCKS

			#if false
			var all_prod_patient_apps = new List<Guid>()
			{
				CommonValues.AccountIdForDexcomCgmMobileApp_OUS_PROD,
				CommonValues.AccountIdForDexcomCgmMobileG6App_PROD,
				CommonValues.AccountIdForDexcomBulkDataPublisherG6PhoneApp_PROD,
				CommonValues.AccountIdForDexcomSharePublisherApp_PROD,
				CommonValues.AccountIdForDexcomCgmMobileApp_PROD,
				CommonValues.AccountIdForDexcomCgmMobile10KApp_PROD,
				CommonValues.AccountIdForDexcomShareSubscriberApp_PROD,
				CommonValues.AccountIdForDexcomShareSubscriberApp_OUS_PROD,
				CommonValues.AccountIdForDexcomFusionApp_US_PROD,
				CommonValues.AccountIdForDexcomNewOrionApp_US_PROD,
				CommonValues.AccountIdForDexcomCgmMobileG7App_PROD,
				CommonValues.AccountIdForDexcomBulkDataPublisherPhoneApp_PROD,
				CommonValues.AccountIdForDexcomBulkDataPublisherG6PhoneApp_PROD,
				CommonValues.AccountIdForDexcomBulkDataPublisherUploaderApp_PROD,
				CommonValues.AccountIdForDexcomBulkDataPublisherUploaderApp_OUS_PROD,
			};
			#endif

			#region GET / CREATE PATIENT ACCOUNT
			var smoke_patient_guid = DoCallFunction(() => share_service.AuthenticatePublisherAccount(context.SmokePatient_AppId, context.SmokePatient_Username, context.SmokePatient_Password), "share_service.AuthenticatePublisherAccount");
			if (smoke_patient_guid == Guid.Empty)
			{
				smoke_patient_guid  = DoCallFunction(()=> share_service.CreatePublisherAccount(context.SmokePatient_AppId, context.SmokePatient_Username, context.SmokePatient_Displayname, context.SmokePatient_Email, context.SmokePatient_Password), "share_service.CreatePublisherAccount");
			}

			if (smoke_patient_guid == Guid.Empty)
			{
				throw new Exception("Smoke patient account guid is EMPTY.  Can't continue!");
			}
            Messages.Add($"Smoke Patient Id = {smoke_patient_guid}");

			#endregion GET / CREATE PATIENT ACCOUNT

            #region DEVICE KEY

            if (context.CheckDeviceKey)
			{
				smoke_patient_device_secret = DoRegisterDeviceKey(share_service, context.SmokePatient_AppId, smoke_patient_guid, device_key, context.RsaKeyId, context.SmokePatient_Password, isPublisher: true);
				for (int i = 0; i < 8; i++)
				{
					var header = new RequestHeader() {AccountId = smoke_patient_guid, ApplicationId = context.SmokePatient_AppId, Timestamp = DateTimeOffset.Now, IsPayloadZipped = false};
					var payload = new EventTypesPayload() {EventTypes = "Message",}; // ANY or even empty payload will work with CheckDeviceKey
					if (i > 3)
					{
						header.EncryptionKey = new EncryptionKey() { RsaKey = context.RsaKeyId };
					}
					var signed_request = EventsDataUtils.CreateSignedRequest(header, payload, smoke_patient_device_secret, LookupWellKnownPublicOnlyDeviceKeyRsaWrapper);
					DoCallAction(() => share_service.CheckDeviceKey(signed_request.RawRequest), $"CheckDeviceKey@i={i}");
				}

				{
					var header = new RequestHeader() {AccountId = smoke_patient_guid, ApplicationId = context.SmokePatient_AppId, Timestamp = DateTimeOffset.Now, IsPayloadZipped = false};
					var payload = new UpdatePublisherAccountPayload() {DisplayName = context.SmokePatient_Displayname + DateTimeOffset.Now.TimeOfDay.Seconds.ToString("D2"), EmailAddress = context.SmokePatient_Email, CountryCode = context.SmokePatient_Country, LanguageCode = context.SmokePatient_Language,};
					var signed_request = EventsDataUtils.CreateSignedRequest(header, payload, smoke_patient_device_secret);
					DoCallAction(() => share_service.UpdatePublisherAccount(signed_request.RawRequest), "share_service.UpdatePublisherAccount");
				}
			}

			#endregion DEVICE KEY

			#region APP COMPAT

			if (context.CheckAppCompat)
			{
				// iOS Apple
				{
					Messages.Add($"Starting iOS APPLE App Compat service tests.");
                    var unsupport_runtime = context.AppleUnsupportedRuntime;
					var support_runtime = context.AppleSupportedRuntime;

					var validity_result = DoCallFunction(() => app_compat_service.CheckValidity(context.SmokePatient_AppId, unsupport_runtime), "app_compat_service.CheckValidity");
					Assert.AreEqual("InvalidUnsupportedEnvironment", validity_result.Validity, "APPLE: validity_result.Validity == 'InvalidUnsupportedEnvironment'");
					Assert.IsTrue(validity_result.MessageId != Guid.Empty, "APPLE: validity_result.MessageId != Guid.Empty");

					if (validity_result.MessageId != Guid.Empty)
					{
						var message_result = DoCallFunction(() => app_compat_service.GetMessage(context.SmokePatient_AppId, validity_result.MessageId, "en-US"), "app_compat_service.GetMessage");
						Assert.IsTrue(message_result.Message.IsNotNullOrEmpty(), "APPLE: message_result.Message.IsNotNullOrEmpty()");
						Messages.Add($"Message from unsupported iOS Apple environment = {message_result.Message}");
					}

					validity_result = DoCallFunction(() => app_compat_service.CheckValidity(context.SmokePatient_AppId, support_runtime), "app_compat_service.CheckValidity");
					Assert.AreEqual("ValidEnvironment", validity_result.Validity, "APPLE: validity_result.Validity == 'ValidEnvironment'");
					Assert.IsTrue(validity_result.MessageId == Guid.Empty, "APPLE: validity_result.MessageId == Guid.Empty");
				}
				// Android
				{
					Messages.Add($"Starting ANDROID App Compat service tests.");
                    var unsupport_runtime = context.AndroidUnsupportedRuntime;
                    var support_runtime = context.AndroidSupportedRuntime;

                    var validity_result = DoCallFunction(() => app_compat_service.CheckValidity(context.SmokePatient_AppId, unsupport_runtime), "app_compat_service.CheckValidity");
					Assert.AreEqual("InvalidUnsupportedEnvironment", validity_result.Validity, "ANDROID: validity_result.Validity == 'InvalidUnsupportedEnvironment'");
					Assert.IsTrue(validity_result.MessageId != Guid.Empty, "ANDROID: validity_result.MessageId != Guid.Empty");

					if (validity_result.MessageId != Guid.Empty)
					{
						var message_result = DoCallFunction(() => app_compat_service.GetMessage(context.SmokePatient_AppId, validity_result.MessageId, "en-US"), "app_compat_service.GetMessage");
						Assert.IsTrue(message_result.Message.IsNotNullOrEmpty(), "ANDROID: message_result.Message.IsNotNullOrEmpty()");
						Messages.Add($"ANDROID: Message from unsupported android environment = {message_result.Message}");
					}

					validity_result = DoCallFunction(() => app_compat_service.CheckValidity(context.SmokePatient_AppId, support_runtime), "app_compat_service.CheckValidity");
					Assert.AreEqual("ValidEnvironment", validity_result.Validity, "ANDROID: validity_result.Validity == 'ValidEnvironment'");
					Assert.IsTrue(validity_result.MessageId == Guid.Empty, "ANDROID: validity_result.MessageId == Guid.Empty");
				}
			}

			#endregion APP COMPAT

			#region LEGAL

			if (context.CheckLegal)
			{
				var countries = DoCallFunction(() => legal_service.GetSupportedCountryCodes(), "legal_service.GetSupportedCountryCodes");

				var resource_file = "LegalAgreements";
				var dictionary_key = "AgreementsAcceptancePrompt";
				var language_code = context.SmokePatient_Language;
				var country_code = context.SmokePatient_Country;
				var actual_resource_value = DoCallFunction(() => legal_service.GetResource(resource_file, language_code, dictionary_key), "legal_service.GetResource");
				Assert.IsFalse(string.IsNullOrEmpty(actual_resource_value), $"Resource file '{resource_file}' for resource key '{dictionary_key}' and language '{language_code}' returned an empty string, when a value was expected.");

				var client = new OAuth2Client(new Uri(context.StsIdentityService), context.StsClientId, "secret");
				var optional = new Dictionary<string, string> { };
				var token = client.RequestResourceOwnerPasswordAsync(context.SmokePatient_Username, context.SmokePatient_Password, "AccountManagement", optional).Result;

                Assert.IsFalse(token.IsHttpError, $"UAM token has http error: '{token.HttpErrorReason}'");
                Assert.IsFalse(token.IsError, $"UAM token has error: '{token.Error}'");
                Assert.IsFalse(token.AccessToken == null, $"UAM token has null AccessToken");

				var acceptancStatus = DoCallFunction(() => legal_service.InvokeAuthorizedWebServiceCall(token.AccessToken, (service) => service.CheckLegalAcceptanceStatus(country_code, "Test", "10.0.0.0")), "legal_service.CheckLegalAcceptanceStatus");
				Messages.Add($"Acceptance Status (AreAllAccepted) = {acceptancStatus.AreAllAccepted}");

				var agreements = DoCallFunction(() => legal_service.InvokeAuthorizedWebServiceCall(token.AccessToken, (service) => service.GetUserAgreements(country_code, "Test", "10.0.0.0", language_code)), "legal_service.GetUserAgreements");
				foreach (var agreement in agreements)
				{
					Messages.Add($"Agreement Date Accepted = {agreement.DateAccepted}, IsAccepted = {agreement.IsAccepted}, LegalAgreement DisplayName = {agreement.LegalAgreement.DisplayName}");
				}

				var legal_doc = DoCallFunction(() => legal_service.GetContentDocumentData("TermsOfUse", country_code, "Test", "10.0.0.0", language_code, true), "legal_service.GetContentDocumentData");
				Messages.Add($"LegalDoc ContentType = {legal_doc.ContentType}, LegalDoc ContentLength = {legal_doc.ContentLength}, LegalDoc FileName = {legal_doc.FileName}");

				var doc_message = DoCallFunction(() => legal_service.GetContentDocument("TermsOfUse", country_code, "Test", "10.0.0.0", language_code), "legal_service.GetContentDocument");
				Messages.Add($"LegalDoc Message IsEmpty = {doc_message.IsEmpty}");

			}

			#endregion LEGAL

			#region DATA POST

			if (context.CheckDataPost)
			{
				DataPost get_post = null;

				{
					var get_last_post_header = new RequestHeader() {AccountId = smoke_patient_guid, ApplicationId = context.SmokePatient_AppId, Timestamp = DateTimeOffset.Now, IsPayloadZipped = false};
					var get_last_post_payload = new ReadDataPostRequestPayload() {StreamTypeFilter = "Receiver"};
					var get_last_post_signed_request = EventsDataUtils.CreateSignedRequest(get_last_post_header, get_last_post_payload, smoke_patient_device_secret);
					get_post = DoCallFunction(() => datapoast_service.ReadLastDataPost2(get_last_post_signed_request.RawRequest));
				}

				if (get_post != null)
				{
                    Messages.Add($"Found a prior Receiver Data Post: PostTimestamp = {get_post.PostedTimestamp:O}, PostId = {get_post.PostId}");

                    var header = get_post.ExtractDataPostHeader();
					Assert.AreEqual(smoke_patient_guid, header.PatientId);
					var pub_content = get_post.ExtractDataPostPublicContent(smoke_patient_guid);
					var pub_manifest = get_post.ExtractDataPostPublicManifest(smoke_patient_guid);
					var priv_content = get_post.ExtractDataPostPrivateContent(smoke_patient_guid);
					var priv_manifest = get_post.ExtractDataPostPrivateManifest(smoke_patient_guid);
					Assert.AreEqual(DataStreamType.Receiver, header.SourceStream);
				}
                else
                {
                    Messages.Add($"Did NOT find any last data post by Smoke Patient under test!");
                }

                // Post a new one at least every 5 seconds.
                if (get_post == null || (DateTimeOffset.Now - get_post.PostedTimestamp).Duration() > TimeSpan.FromSeconds(5))
				{
					var put_post_header = new RequestHeader() {AccountId = smoke_patient_guid, ApplicationId = context.SmokePatient_AppId, Timestamp = DateTimeOffset.Now, IsPayloadZipped = false};
					var put_post_payload = new DataPostRequestPayload() {DataPost = CreateSmokeDataPost(smoke_patient_guid)};
					var put_post_signed_request = EventsDataUtils.CreateSignedRequest(put_post_header, put_post_payload, smoke_patient_device_secret);
					smoked_new_data_post_id = DoCallFunction(() => datapoast_service.PostPatientData2(put_post_signed_request.RawRequest));

                    Messages.Add($"SmokeTest patient posted a new data post: PostId = {smoked_new_data_post_id} result @ {DateTimeOffset.Now:O}");

                    {
                        var get_last_post_header = new RequestHeader() { AccountId = smoke_patient_guid, ApplicationId = context.SmokePatient_AppId, Timestamp = DateTimeOffset.Now, IsPayloadZipped = false };
						var get_last_post_payload = new ReadDataPostRequestPayload() { StreamTypeFilter = "Receiver" };
						var get_last_post_signed_request = EventsDataUtils.CreateSignedRequest(get_last_post_header, get_last_post_payload, smoke_patient_device_secret);
						get_post = DoCallFunction(() => datapoast_service.ReadLastDataPost2(get_last_post_signed_request.RawRequest));

						Assert.AreEqual(smoked_new_data_post_id, get_post.PostId, "Failed to retrieve 'ReadLastPost' equal to brand new post!");
					}
				}
			}
			#endregion DATA POST

			#region TEST ADMIN CALLS

			if (context.CheckAdminCalls)
			{
				var admin_session = DoCallFunction(() => admin_login_service.LoginByUserName(CommonValues.SystemIdForShare, context.SmokeAdmin_Username, CommonValues.ProductIdForShareSupportTool_PROD, context.SmokeAdmin_Password), "admin_login_service.LoginByUserName");
				var datasync_session = DoCallFunction(() => datasync_service.LoginByName(CommonValues.SystemIdForShareDataSync, context.SmokeAdmin_Username, CommonValues.ProductIdForDexcomBulkDataConsumer, context.SmokeAdmin_Password), "datasync_service.LoginByName");

				var table_space = DoCallFunction(() => share_admin_service.ReportDatabaseTableSpace(admin_session), "share_admin_service.ReportDatabaseTableSpace");
				XmlDocument x_doc = new XmlDocument();
				x_doc.LoadXml(table_space);
				XObject x_table_space = new XObject(x_doc.DocumentElement);
				//Messages.Add(CommonTools.FormatXml(x_doc));
				var x_tables = new XCollection<XTable>(x_table_space.Element);

				{
					var x_work_queue_table = x_tables.First(table => table.Name == "oWorkQueue");
					if (x_work_queue_table.Rows > 1000)
					{
						Exceptions.Add($"{(context.IsProduction ? "ERROR" : "WARNING")}: Table 'oWorkQueue' has more than 1000 entries indicating work items NOT being serviced and will degrade system performance!");
					}
					Messages.Add($"Database tables 'oWorkQueue' rows = {x_work_queue_table.Rows:N0}");
				}
				{
					var x_lsn_time_mapping = x_tables.First(table => table.Name == "lsn_time_mapping");
					if (x_lsn_time_mapping.Rows > 100000)
					{
						Exceptions.Add($"{(context.IsProduction ? "ERROR" : "WARNING")}: Table 'lsn_time_mapping' has more than 100,000 entries indicating CDC cleanup job may be stopped!");
					}
					Messages.Add($"Database tables 'lsn_time_mapping' rows = {x_lsn_time_mapping.Rows:N0}");
				}
				{
					long total_rows = 0;
					x_tables.ForEach(table => total_rows += table.Rows);
					Messages.Add($"Database tables total rows = {total_rows:N0}");
				}
				{
					long total_space = 0;
					x_tables.ForEach(table => total_space += table.TotalKB);
					Messages.Add($"Database tables total space (free + used) = {total_space:N0} KB");
				}
				{
					long used_space = 0;
					x_tables.ForEach(table => used_space += table.UsedSKB);
					Messages.Add($"Database tables total space (actual used only) = {used_space:N0} KB");
				}
				{
					long unused_space = 0;
					x_tables.ForEach(table => unused_space += table.UnusedKB);
					Messages.Add($"Database tables total space (free space only) = {unused_space:N0} KB");
				}

				var is_caller_privileged_manage_users = DoCallFunction(() => user_service.IsCallerPrivileged(admin_session, "PrivilegeManageUsers"), "user_service.IsCallerPrivileged");
				if (is_caller_privileged_manage_users)
				{
					try
					{
						var x_bootstrap_user = DoCallFunction(() => user_service.GetUserByName(admin_session, "DeleteMeBootstrap"), "user_service.GetUserByName(admin_session, 'DeleteMeBootstrap')");
						if (x_bootstrap_user.IsActive)
						{
							Exceptions.Add($"{(context.IsProduction ? "ERROR" : "WARNING")}: 'DeleteMeBootstrap' user exists in target system and is ACTIVE");
						}
					}
					catch (WebFaultException<WebServiceException> exception)
					{
						if (exception.Detail.Code != "ObjectNotFound")
						{
							throw;
						}
					}
					try
					{
						var x_bootstrap_user = DoCallFunction(() => user_service.GetUserByName(admin_session, "TestingAdmin"), "user_service.GetUserByName(admin_session, 'TestingAdmin')");
						if (x_bootstrap_user.IsActive)
						{
							Exceptions.Add($"{(context.IsProduction ? "ERROR" : "WARNING")}: 'TestingAdmin' user exists in target system and is ACTIVE");
						}
					}
					catch (WebFaultException<WebServiceException> exception)
					{
						if (exception.Detail.Code != "ObjectNotFound")
						{
							throw;
						}
					}
				}
				else
				{
					Exceptions.Add("ERROR: SmokeAdminUser is not privileged for ManageUsers.");
				}

                // Find last smoked post.
                if (smoked_new_data_post_id != Guid.Empty)
                {
                    var newest_post = DoCallFunction(() => datasync_service.ReadPatientDataPostById(datasync_session, smoke_patient_guid, smoked_new_data_post_id), "datasync_service.ReadPatientDataPostById");

                    if (newest_post == null)
                    {
                        Exceptions.Add($"ERROR: Synching the just smoked data post by post id failed (returned null) as if it doesn't exist!?");
                    }
                    else
                    {
                        Messages.Add($"Just smoked data post arrived {(DateTimeOffset.Now - newest_post.PostedTimestamp)} ago. PostId = {newest_post.PostId}, PostedTimestamp = {newest_post.PostedTimestamp:O}");

                        if ((newest_post.PostedTimestamp - DateTimeOffset.Now).Duration() > TimeSpan.FromSeconds(30))
                        {
                            Exceptions.Add($"ERROR: Just smoked data post arrived more than 30 seconds ago at {newest_post.PostedTimestamp:O} about {(DateTimeOffset.Now - newest_post.PostedTimestamp)} ago ... STALLED OUT!?");
                        }
                    }
                }

                // Find any last post
                {
                    var newest_post_number = DoCallFunction(() => datasync_service.ReadDataPostNumber(datasync_session, true), "datasync_service.ReadDataPostNumber");
                    Messages.Add($"Newest data post number = {newest_post_number} 1st call");
                    newest_post_number = DoCallFunction(() => datasync_service.ReadDataPostNumber(datasync_session, true), "datasync_service.ReadDataPostNumber");
                    Messages.Add($"Newest data post number = {newest_post_number} 2nd call");

                    var newest_post = DoCallFunction(() => datasync_service.SyncDataPostByNumber(datasync_session, newest_post_number), "datasync_service.SyncDataPostByNumber");
                    if (newest_post == null)
                    {
                        Exceptions.Add($"ERROR: Synching the newest datapost number failed (returned null) as if it doesn't exist. Possible but not probable!?");
                    }
                    else
                    {
                        Messages.Add($"Newest data post arrived {(DateTimeOffset.Now - newest_post.PostedTimestamp)} ago. PostId = {newest_post.PostId}, PostedTimestamp = {newest_post.PostedTimestamp:O}");

                        if ((newest_post.PostedTimestamp - DateTimeOffset.Now).Duration() > TimeSpan.FromSeconds(30))
                        {
                            Exceptions.Add($"ERROR: Newest datapost arrived more than 30 seconds ago at {newest_post.PostedTimestamp:O} about {(DateTimeOffset.Now - newest_post.PostedTimestamp)} ago ... STALLED OUT!?");
                        }
                    }
                }

                #region APP COMPAT (ADMIN)

				#endregion APP COMPAT (ADMIN)
			}
			#endregion TEST ADMIN CALLS

			return new XObject("SmokeTest");
		}

        #region OUS ... LIFT_N_SHIFT TESTING

        /// <summary>
        /// The one when running under NUNIT.
        /// </summary>
        //[Test]
        public void NUNIT_SmokeTest_PROD_OUS_GCP_LIFT_N_SHIFT()
		{
			try
			{
				SmokeTest_PROD_OUS_GCP_LIFT_N_SHIFT();
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}
		}

		/// <summary>
		/// The one when running under NUNIT.
		/// </summary>
		//[Test]
		public void NUNIT_SmokeTest_PROD_OUS_PRE_LIFT()
		{
			try
			{
				SmokeTest_PROD_OUS_PRE_LIFT();
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}
		}

		/// <summary>
		/// The one when running under NUNIT.
		/// </summary>
		//[Test]
		public void NUNIT_SmokeTest_PROD_OUS_POST_LIFT()
		{
			try
			{
				SmokeTest_PROD_OUS_POST_LIFT();
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}
		}

		/// <summary>
		/// The one when running under NUNIT.
		/// </summary>
		//[Test]
		public void NUNIT_SmokeTest_TEST_OUS_GCP_LIFT_N_SHIFT()
		{
			try
			{
				SmokeTest_TEST_OUS_GCP_LIFT_N_SHIFT();
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}
		}

		/// <summary>
		/// The real one to call from outside ... like PRTG or PowerShell
		/// </summary>
		public void SmokeTest_PROD_OUS_GCP_LIFT_N_SHIFT()
		{
			Initialize();

			DateTimeOffset start_time = DateTimeOffset.Now;

			try
			{
				RunSmokeTest(new SmokeTestContext_PROD_OUS_GCP_LIFT_N_SHIFT());
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}

			DateTimeOffset stop_time = DateTimeOffset.Now;

			Console.WriteLine($"Elapsed Time = {stop_time - start_time}, Time Start = {start_time:O}, Finish Time = {stop_time:O}");
			DoDumpResultToConsole();
		}

		/// <summary>
		/// The real one to call from outside ... like PRTG or PowerShell
		/// </summary>
		public void SmokeTest_PROD_OUS_PRE_LIFT()
		{
			Initialize();

			DateTimeOffset start_time = DateTimeOffset.Now;

			try
			{
				RunSmokeTest(new SmokeTestContext_PROD_OUS_PRE_LIFT());
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}

			DateTimeOffset stop_time = DateTimeOffset.Now;

			Console.WriteLine($"Elapsed Time = {stop_time - start_time}, Time Start = {start_time:O}, Finish Time = {stop_time:O}");
			DoDumpResultToConsole();
		}

		/// <summary>
		/// The real one to call from outside ... like PRTG or PowerShell
		/// </summary>
		public void SmokeTest_PROD_OUS_POST_LIFT()
		{
			Initialize();

			DateTimeOffset start_time = DateTimeOffset.Now;

			try
			{
				RunSmokeTest(new SmokeTestContext_PROD_OUS_POST_LIFT());
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}

			DateTimeOffset stop_time = DateTimeOffset.Now;

			Console.WriteLine($"Elapsed Time = {stop_time - start_time}, Time Start = {start_time:O}, Finish Time = {stop_time:O}");
			DoDumpResultToConsole();
		}

		/// <summary>
		/// The real one to call from outside ... like PRTG or PowerShell
		/// </summary>
		public void SmokeTest_TEST_OUS_GCP_LIFT_N_SHIFT()
		{
			Initialize();

			DateTimeOffset start_time = DateTimeOffset.Now;

			try
			{
				RunSmokeTest(new SmokeTestContext_TEST_OUS_GCP_LIFT_N_SHIFT());
			}
			catch (Exception exception)
			{
				Console.WriteLine(DoProcessException(exception));
			}

			DateTimeOffset stop_time = DateTimeOffset.Now;

			Console.WriteLine($"Elapsed Time = {stop_time - start_time}, Time Start = {start_time:O}, Finish Time = {stop_time:O}");
			DoDumpResultToConsole();
		}

        #endregion OUS ... LIFT_N_SHIFT TESTING

        #region US ... LIFT_N_SHIFT from ScaleMatrix TO GCP

        /// <summary>
        /// The one when running under NUNIT.
        /// </summary>
        [Test(Description = "Run this to test US Production URLs (before cutover is against ScaleMatrix, after cutover is against GCP, before cutover with HOSTS file is to try GCP before DNS change is live."), Ignore("Lift and Shift Test")]
        public void NUNIT_SmokeTest_PROD_US_POST_CUTOVER()
        {
            try
            {
                SmokeTest_PROD_US_POST_CUTOVER();
            }
            catch (Exception exception)
            {
                Console.WriteLine(DoProcessException(exception));
            }
        }

        /// <summary>
        /// The one when running under NUNIT.
        /// </summary>
        [Test(Description = "Run this to test Share2Cutover.dexcom.com and suite of URLs for practicing before configuration are prod-ready.")]
        public void NUNIT_SmokeTest_PROD_US_CUTOVER()
        {
            try
            {
                SmokeTest_PROD_US_CUTOVER();
            }
            catch (Exception exception)
            {
                Console.WriteLine(DoProcessException(exception));
            }
        }

        /// <summary>
        /// The real one to call from outside ... like PRTG or PowerShell
        /// </summary>
        public void SmokeTest_PROD_US_POST_CUTOVER()
        {
            Initialize();

            DateTimeOffset start_time = DateTimeOffset.Now;

            try
            {
                RunSmokeTest(new SmokeTestContext_PROD_US_POST_CUTOVER());
            }
            catch (Exception exception)
            {
                Console.WriteLine(DoProcessException(exception));
            }

            DateTimeOffset stop_time = DateTimeOffset.Now;

            Console.WriteLine($"Elapsed Time = {stop_time - start_time}, Time Start = {start_time:O}, Finish Time = {stop_time:O}");
            DoDumpResultToConsole();
        }

       /// <summary>
        /// The real one to call from outside ... like PRTG or PowerShell
        /// </summary>
        public void SmokeTest_PROD_US_CUTOVER()
        {
            Initialize();

            DateTimeOffset start_time = DateTimeOffset.Now;

            try
            {
                RunSmokeTest(new SmokeTestContext_PROD_US_CUTOVER());
            }
            catch (Exception exception)
            {
                Console.WriteLine(DoProcessException(exception));
            }

            DateTimeOffset stop_time = DateTimeOffset.Now;

            Console.WriteLine($"Elapsed Time = {stop_time - start_time}, Time Start = {start_time:O}, Finish Time = {stop_time:O}");
            DoDumpResultToConsole();
        }

        #endregion US ... LIFT_N_SHIFT from ScaleMatrix TO GCP

        #region US ... UAT

	    /// <summary>
	    /// The one when running under NUNIT.
	    /// </summary>
	    [Test(Description = "Run this to test US Production URLs (before cutover is against ScaleMatrix, after cutover is against GCP, before cutover with HOSTS file is to try GCP before DNS change is live.")]
	    public void NUNIT_SmokeTest_UAT_US()
	    {
	        try
	        {
	            SmokeTest_UAT_US();
	        }
	        catch (Exception exception)
	        {
	            Console.WriteLine(DoProcessException(exception));
	        }
	    }

	    /// <summary>
	    /// The real one to call from outside ... like PRTG or PowerShell
	    /// </summary>
	    public void SmokeTest_UAT_US()
	    {
	        Initialize();

	        DateTimeOffset start_time = DateTimeOffset.Now;

	        try
	        {
	            RunSmokeTest(new SmokeTestContext_UAT_US());
	        }
	        catch (Exception exception)
	        {
	            Console.WriteLine(DoProcessException(exception));
	        }

	        DateTimeOffset stop_time = DateTimeOffset.Now;

	        Console.WriteLine($"Elapsed Time = {stop_time - start_time}, Time Start = {start_time:O}, Finish Time = {stop_time:O}");
	        DoDumpResultToConsole();
	    }

        #endregion
    }

    public interface ISmokeTestContext
	{
		bool IsProduction { get; }

		string ShareWebServices { get; }
		string ShareDataPostWebServices { get; }
		string AppCompatibilityWebServices { get; }
		string LegalWebServices { get; }

		string ShareAdminWebServices { get; }
		string ShareAdminWebServices_Login { get; }
		string ShareAdminWebServices_User { get; }
		string AppCompatibilityAdminWebServices { get; }
		string ShareDataSyncWebServices { get; }
		string ShareUAMWebServices { get; }

		string StsIdentityService { get; }

		string StsClientId { get; }
		string SmokePatient_Username { get; }
		string SmokePatient_Displayname { get; }
		string SmokePatient_Password { get; }
		string SmokePatient_Email { get; }
		string SmokePatient_Country { get; }
		string SmokePatient_Language { get; }
		Guid SmokePatient_AppId { get; }

		string SmokeAdmin_Username { get; }
		string SmokeAdmin_Password { get; }

		int RsaKeyId { get; }

        ApplicationRuntimeInfo AppleSupportedRuntime { get; }
        ApplicationRuntimeInfo AppleUnsupportedRuntime { get; }
        ApplicationRuntimeInfo AndroidSupportedRuntime { get; }
        ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; }

        bool CheckClocks { get; }
		bool CheckAppCompat { get; } 
		bool CheckLegal { get; }
		bool CheckDeviceKey { get; }
		bool CheckDataPost { get; }
        bool CheckAdminCalls { get; }
	}
    
    #region OUS ... LIFT_N_SHIFT TESTING

    public class SmokeTestContext_PROD_OUS_GCP_LIFT_N_SHIFT : ISmokeTestContext
	{
		public bool IsProduction { get; } = true;
		public bool CheckAdminCalls { get; } = true;
		public string ShareWebServices { get; } = "https://shareous1prodgcp.dexcom.com/ShareWebServices/Services";
		public string ShareDataPostWebServices { get; } = "https://shareous1prodgcp.dexcom.com/ShareDataPostWebServices/Services";
		public string AppCompatibilityWebServices { get; } = "https://shareous1prodgcp.dexcom.com/AppCompatibilityWebServices/Services";
		public string LegalWebServices { get; } = "https://shareous1prodgcp.dexcom.com/LegalWebServices/Services";

		public string ShareAdminWebServices { get; } = "https://shareadminous1prodgcp.dexcom.com/ShareAdminWebServices/Services";
		public string ShareAdminWebServices_Login { get; } = "https://shareadminous1prodgcp.dexcom.com/ShareAdminWebServices/Login";
		public string ShareAdminWebServices_User { get; } = "https://shareadminous1prodgcp.dexcom.com/ShareAdminWebServices/User";
		public string AppCompatibilityAdminWebServices { get; } = "https://shareadminous1prodgcp.dexcom.com/AppCompatibilityAdminWebServices/Services";
		public string ShareDataSyncWebServices { get; } = "https://shareadminous1prodgcp.dexcom.com/ShareDataSyncWebServices/Services";
		public string ShareUAMWebServices { get; } = "https://shareadminous1prodgcp.dexcom.com/ShareUAMWebServices/Services";

		public string StsIdentityService { get; } = "https://uam2.dexcom.com/identity/connect/token";

		public string StsClientId { get; } = "0D742E37-71F9-4363-8B25-57D09A05F712";
		public string SmokePatient_Username { get; } = "DexcomSmokeTest";
		public string SmokePatient_Displayname { get; } = "Dexcom Smoke Test";
		public string SmokePatient_Password { get; } = "Dexcom1";
		public string SmokePatient_Email { get; } = "noreply@rnd-dexcom.com";
		public string SmokePatient_Country { get; } = "GB";
		public string SmokePatient_Language { get; } = "en-US";
		public Guid SmokePatient_AppId { get; } = CommonValues.AccountIdForDexcomCgmMobileApp_OUS_PROD;

		public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
		public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

		public int RsaKeyId { get; } = 101;

        public ApplicationRuntimeInfo AppleSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,7", };
        public ApplicationRuntimeInfo AppleUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,1", };
        public ApplicationRuntimeInfo AndroidSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_G5", AppNumber = "SW10940", AppVersion = "1.7.9.1", DeviceOsName = "Android", DeviceOsVersion = "6.0.1", DeviceManufacturer = "samsung", DeviceModel = "SM-S903VL", };
        public ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_G5", AppNumber = "SW10940", AppVersion = "0.0.0.0", DeviceOsName = "Android", DeviceOsVersion = "0.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G1000", };

        public bool CheckClocks { get; } = false;
		public bool CheckAppCompat { get; } = false;
		public bool CheckLegal { get; } = true;
		public bool CheckDeviceKey { get; } = true;
		public bool CheckDataPost { get; } = false;
	}

	[TestFixture]
    public class QuickTest
    {
        public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
        public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

        public string ShareAdminWebServices_Login { get; } = "https://shareadminous1.dexcom.com/ShareAdminWebServices/Login";
        public string ShareDataSyncWebServices { get; } = "https://shareadminous1.dexcom.com/ShareDataSyncWebServices/Services";

        [Test]
        public void QuickCheckReadDataPostNumber()
        {
            var datasync_service = WebServiceTools.MakeRestWebServiceClient<IShareDataSyncWebServices>(ShareDataSyncWebServices);
            var admin_login_service = WebServiceTools.MakeRestWebServiceClient<ILoginWebServices>(ShareAdminWebServices_Login);

            var admin_session = admin_login_service.LoginByUserName(CommonValues.SystemIdForShare, SmokeAdmin_Username, CommonValues.ProductIdForShareSupportTool_PROD, SmokeAdmin_Password);
            var datasync_session = datasync_service.LoginByName(CommonValues.SystemIdForShareDataSync, SmokeAdmin_Username, CommonValues.ProductIdForDexcomBulkDataConsumer, SmokeAdmin_Password);

            var newest_post_number = datasync_service.ReadDataPostNumber(datasync_session, true);
            Console.WriteLine($"Newest data post number = {newest_post_number} 1st call");
            Thread.Sleep(1000);
            newest_post_number = datasync_service.ReadDataPostNumber(datasync_session, true);
            Console.WriteLine($"Newest data post number = {newest_post_number} 2nd call 1 second later");
            var oldest_post_number = datasync_service.ReadDataPostNumber(datasync_session, false);
            Console.WriteLine($"Oldest data post number = {oldest_post_number}");
        }
    }

    public class SmokeTestContext_PROD_OUS_PRE_LIFT : ISmokeTestContext
	{
		public bool IsProduction { get; } = true;
		public bool CheckAdminCalls { get; } = true;
		public string ShareWebServices { get; } = "https://shareous1.dexcom.com/ShareWebServices/Services";
		public string ShareDataPostWebServices { get; } = "https://shareous1.dexcom.com/ShareDataPostWebServices/Services";
		public string AppCompatibilityWebServices { get; } = "https://shareous1.dexcom.com/AppCompatibilityWebServices/Services";
		public string LegalWebServices { get; } = "https://shareous1.dexcom.com/LegalWebServices/Services";

		public string ShareAdminWebServices { get; } = "https://shareadminous1.dexcom.com/ShareAdminWebServices/Services";
		public string ShareAdminWebServices_Login { get; } = "https://shareadminous1.dexcom.com/ShareAdminWebServices/Login";
		public string ShareAdminWebServices_User { get; } = "https://shareadminous1.dexcom.com/ShareAdminWebServices/User";
		public string AppCompatibilityAdminWebServices { get; } = "https://shareadminous1.dexcom.com/AppCompatibilityAdminWebServices/Services";
		public string ShareDataSyncWebServices { get; } = "https://shareadminous1.dexcom.com/ShareDataSyncWebServices/Services";
		public string ShareUAMWebServices { get; } = "https://shareous1.dexcom.com/ShareUAMWebServices/Services"; // NOTE: this url is NOT admin (like it is correctly later on) but is still whitelisted/protected.

		public string StsIdentityService { get; } = "https://uam2.dexcom.com/identity/connect/token";

		public string StsClientId { get; } = "0D742E37-71F9-4363-8B25-57D09A05F712";
		public string SmokePatient_Username { get; } = "DexcomSmokeTest";
		public string SmokePatient_Displayname { get; } = "Dexcom Smoke Test";
		public string SmokePatient_Password { get; } = "Dexcom1";
		public string SmokePatient_Email { get; } = "noreply@rnd-dexcom.com";
		public string SmokePatient_Country { get; } = "GB";
		public string SmokePatient_Language { get; } = "en-US";
		public Guid SmokePatient_AppId { get; } = CommonValues.AccountIdForDexcomCgmMobileApp_OUS_PROD;

		public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
		public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

		public int RsaKeyId { get; } = 101;

        public ApplicationRuntimeInfo AppleSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW10842", AppVersion = "1.7.1", DeviceOsName = "iPhone OS", DeviceOsVersion = "11.2.6", DeviceManufacturer = "Apple", DeviceModel = "iPad2,7", };
        public ApplicationRuntimeInfo AppleUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_IPAD", AppNumber = "SW10842", AppVersion = "1.7.1", DeviceOsName = "iPhone OS", DeviceOsVersion = "11.2.6", DeviceManufacturer = "Apple", DeviceModel = "iPad1,1", };
        public ApplicationRuntimeInfo AndroidSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW11170", AppVersion = "1.2.0.1", DeviceOsName = "Android", DeviceOsVersion = "7.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G930", };
        public ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW11170", AppVersion = "1.2.0.1", DeviceOsName = "Android", DeviceOsVersion = "6.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G930", };

        public bool CheckClocks { get; } = true;
		public bool CheckAppCompat { get; } = true;
		public bool CheckLegal { get; } = true;
		public bool CheckDeviceKey { get; } = true;
		public bool CheckDataPost { get; } = true;
	}

	public class SmokeTestContext_PROD_OUS_POST_LIFT : ISmokeTestContext
	{
		public bool IsProduction { get; } = true;
		public bool CheckAdminCalls { get; } = true;
		public string ShareWebServices { get; } = "https://shareous1.dexcom.com/ShareWebServices/Services";
		public string ShareDataPostWebServices { get; } = "https://shareous1.dexcom.com/ShareDataPostWebServices/Services";
		public string AppCompatibilityWebServices { get; } = "https://shareous1.dexcom.com/AppCompatibilityWebServices/Services";
		public string LegalWebServices { get; } = "https://shareous1.dexcom.com/LegalWebServices/Services";

		public string ShareAdminWebServices { get; } = "https://shareadminous1.dexcom.com/ShareAdminWebServices/Services";
		public string ShareAdminWebServices_Login { get; } = "https://shareadminous1.dexcom.com/ShareAdminWebServices/Login";
		public string ShareAdminWebServices_User { get; } = "https://shareadminous1.dexcom.com/ShareAdminWebServices/User";
		public string AppCompatibilityAdminWebServices { get; } = "https://shareadminous1.dexcom.com/AppCompatibilityAdminWebServices/Services";
		public string ShareDataSyncWebServices { get; } = "https://shareadminous1.dexcom.com/ShareDataSyncWebServices/Services";
		public string ShareUAMWebServices { get; } = "https://shareadminous1.dexcom.com/ShareUAMWebServices/Services"; // NOTE: this url IS hosted admin (unline PRE lift-n-shift).

		public string StsIdentityService { get; } = "https://uam2.dexcom.com/identity/connect/token";

		public string StsClientId { get; } = "0D742E37-71F9-4363-8B25-57D09A05F712";
		public string SmokePatient_Username { get; } = "DexcomSmokeTest";
		public string SmokePatient_Displayname { get; } = "Dexcom Smoke Test";
		public string SmokePatient_Password { get; } = "Dexcom1";
		public string SmokePatient_Email { get; } = "noreply@rnd-dexcom.com";
		public string SmokePatient_Country { get; } = "GB";
		public string SmokePatient_Language { get; } = "en-US";
		public Guid SmokePatient_AppId { get; } = CommonValues.AccountIdForDexcomCgmMobileApp_OUS_PROD;

		public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
		public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

		public int RsaKeyId { get; } = 101;

        public ApplicationRuntimeInfo AppleSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW10842", AppVersion = "1.7.1", DeviceOsName = "iPhone OS", DeviceOsVersion = "11.2.6", DeviceManufacturer = "Apple", DeviceModel = "iPad2,7", };
        public ApplicationRuntimeInfo AppleUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_IPAD", AppNumber = "SW10842", AppVersion = "1.7.1", DeviceOsName = "iPhone OS", DeviceOsVersion = "11.2.6", DeviceManufacturer = "Apple", DeviceModel = "iPad1,1", };
        public ApplicationRuntimeInfo AndroidSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW11170", AppVersion = "1.2.0.1", DeviceOsName = "Android", DeviceOsVersion = "7.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G930", };
        public ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW11170", AppVersion = "1.2.0.1", DeviceOsName = "Android", DeviceOsVersion = "6.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G930", };

		public bool CheckClocks { get; } = true;
		public bool CheckAppCompat { get; } = true;
		public bool CheckLegal { get; } = true;
		public bool CheckDeviceKey { get; } = true;
		public bool CheckDataPost { get; } = true;
	}

	public class SmokeTestContext_TEST_OUS_GCP_LIFT_N_SHIFT : ISmokeTestContext
	{
		public bool IsProduction { get; } = false;
		public bool CheckAdminCalls { get; } = false;
		public string ShareWebServices { get; } = "https://shareous1staging.dexcom.com/ShareWebServices/Services";
		public string ShareDataPostWebServices { get; } = "https://shareous1staging.dexcom.com/ShareDataPostWebServices/Services";
		public string AppCompatibilityWebServices { get; } = "https://shareous1staging.dexcom.com/AppCompatibilityWebServices/Services";
		public string LegalWebServices { get; } = "https://shareous1staging.dexcom.com/LegalWebServices/Services";

		public string ShareAdminWebServices { get; } = "https://shareadminous1staging.dexcom.com/ShareAdminWebServices/Services";
		public string ShareAdminWebServices_Login { get; } = "https://shareadminous1staging.dexcom.com/ShareAdminWebServices/Login";
		public string ShareAdminWebServices_User { get; } = "https://shareadminous1staging.dexcom.com/ShareAdminWebServices/User";
		public string AppCompatibilityAdminWebServices { get; } = "https://shareadminous1staging.dexcom.com/AppCompatibilityAdminWebServices/Services";
		public string ShareDataSyncWebServices { get; } = "https://shareadminous1staging.dexcom.com/ShareDataSyncWebServices/Services";
		public string ShareUAMWebServices { get; } = "https://shareadminous1staging.dexcom.com/ShareUAMWebServices/Services";

		public string StsIdentityService { get; } = "https://uam2staging.dexcom.com/identity/connect/token";

		public string StsClientId { get; } = "0D742E37-71F9-4363-8B25-57D09A05F712";
		public string SmokePatient_Username { get; } = "DexcomSmokeTest";
		public string SmokePatient_Displayname { get; } = "Dexcom Smoke Test";
		public string SmokePatient_Password { get; } = "Dexcom1";
		public string SmokePatient_Email { get; } = "noreply@rnd-dexcom.com";
		public string SmokePatient_Country { get; } = "GB";
		public string SmokePatient_Language { get; } = "en-US";
		public Guid SmokePatient_AppId { get; } = CommonValues.AccountIdForDexcomCgmMobileApp_OUS_PROD;

		public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
		public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

		public int RsaKeyId { get; } = 101;

        public ApplicationRuntimeInfo AppleSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW10842", AppVersion = "1.7.1", DeviceOsName = "iPhone OS", DeviceOsVersion = "11.2.6", DeviceManufacturer = "Apple", DeviceModel = "iPad2,7", };
        public ApplicationRuntimeInfo AppleUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_IPAD", AppNumber = "SW10842", AppVersion = "1.7.1", DeviceOsName = "iPhone OS", DeviceOsVersion = "11.2.6", DeviceManufacturer = "Apple", DeviceModel = "iPad1,1", };
        public ApplicationRuntimeInfo AndroidSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW11170", AppVersion = "1.2.0.1", DeviceOsName = "Android", DeviceOsVersion = "7.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G930", };
        public ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW11170", AppVersion = "1.2.0.1", DeviceOsName = "Android", DeviceOsVersion = "6.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G930", };

		public bool CheckClocks { get; } = true;
		public bool CheckAppCompat { get; } = false;
		public bool CheckLegal { get; } = false;
		public bool CheckDeviceKey { get; } = false;
		public bool CheckDataPost { get; } = false;
	}

    #endregion OUS ... LIFT_N_SHIFT TESTING

    #region US ... LIFT_N_SHIFT from ScaleMatrix TO GCP

    public class SmokeTestContext_PROD_US_POST_CUTOVER : ISmokeTestContext
    {
        public bool IsProduction { get; } = true;

        public string ShareWebServices { get; } = "https://Share2.dexcom.com/ShareWebServices/Services";
        public string ShareDataPostWebServices { get; } = "https://Share2.dexcom.com/ShareDataPostWebServices/Services";
        public string AppCompatibilityWebServices { get; } = "https://Share2.dexcom.com/AppCompatibilityWebServices/Services";
        public string LegalWebServices { get; } = "https://Share2.dexcom.com/LegalWebServices/Services";

        public string ShareAdminWebServices { get; } = "https://Shareadmin3.dexcom.com/ShareAdminWebServices/Services";
        public string ShareAdminWebServices_Login { get; } = "https://Shareadmin3.dexcom.com/ShareAdminWebServices/Login";
        public string ShareAdminWebServices_User { get; } = "https://Shareadmin3.dexcom.com/ShareAdminWebServices/User";
        public string AppCompatibilityAdminWebServices { get; } = "https://Shareadmin3.dexcom.com/AppCompatibilityAdminWebServices/Services";
        public string ShareDataSyncWebServices { get; } = "https://Shareadmin3.dexcom.com/ShareDataSyncWebServices/Services";
        public string ShareUAMWebServices { get; } = "https://Shareadmin3.dexcom.com/ShareUAMWebServices/Services";

        public string StsIdentityService { get; } = "https://uam1.dexcom.com/identity/connect/token";

        public string StsClientId { get; } = "0D742E37-71F9-4363-8B25-57D09A05F712";
        public string SmokePatient_Username { get; } = "DexcomSmokeTest";
        public string SmokePatient_Displayname { get; } = "Dexcom Smoke Test";
        public string SmokePatient_Password { get; } = "Dexcom1";
        public string SmokePatient_Email { get; } = "noreply@rnd-dexcom.com";
        public string SmokePatient_Country { get; } = "US";
        public string SmokePatient_Language { get; } = "en-US";
        public Guid SmokePatient_AppId { get; } = CommonValues.AccountIdForDexcomCgmMobileApp_PROD;

        public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
        public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

        public int RsaKeyId { get; } = 101;

        public ApplicationRuntimeInfo AppleSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,7", };
        public ApplicationRuntimeInfo AppleUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,1", };
        public ApplicationRuntimeInfo AndroidSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_G5", AppNumber = "SW10940", AppVersion = "1.7.9.1", DeviceOsName = "Android", DeviceOsVersion = "6.0.1", DeviceManufacturer = "samsung", DeviceModel = "SM-S903VL", };
        public ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_G5", AppNumber = "SW10940", AppVersion = "0.0.0.0", DeviceOsName = "Android", DeviceOsVersion = "0.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G1000", };

        public bool CheckClocks { get; } = false; // Only do this when you have an extra "few minutes" rather than seconds.
        public bool CheckAppCompat { get; } = true;
        public bool CheckLegal { get; } = true;
        public bool CheckDeviceKey { get; } = true;
        public bool CheckDataPost { get; } = true;
        public bool CheckAdminCalls { get; } = true;
    }

    public class SmokeTestContext_PROD_US_CUTOVER : ISmokeTestContext
    {
        public bool IsProduction { get; } = true;

        public string ShareWebServices { get; } = "https://Share2cutover.dexcom.com/ShareWebServices/Services";
        public string ShareDataPostWebServices { get; } = "https://Share2cutover.dexcom.com/ShareDataPostWebServices/Services";
        public string AppCompatibilityWebServices { get; } = "https://Share2cutover.dexcom.com/AppCompatibilityWebServices/Services";
        public string LegalWebServices { get; } = "https://Share2cutover.dexcom.com/LegalWebServices/Services";

        public string ShareAdminWebServices { get; } = "https://Shareadmin3cutover.dexcom.com/ShareAdminWebServices/Services";
        public string ShareAdminWebServices_Login { get; } = "https://Shareadmin3cutover.dexcom.com/ShareAdminWebServices/Login";
        public string ShareAdminWebServices_User { get; } = "https://Shareadmin3cutover.dexcom.com/ShareAdminWebServices/User";
        public string AppCompatibilityAdminWebServices { get; } = "https://Shareadmin3cutover.dexcom.com/AppCompatibilityAdminWebServices/Services";
        public string ShareDataSyncWebServices { get; } = "https://Shareadmin3cutover.dexcom.com/ShareDataSyncWebServices/Services";
        public string ShareUAMWebServices { get; } = "https://Shareadmin3cutover.dexcom.com/ShareUAMWebServices/Services";

        public string StsIdentityService { get; } = "https://uam1cutover.dexcom.com/identity/connect/token";

        public string StsClientId { get; } = "0D742E37-71F9-4363-8B25-57D09A05F712";
        public string SmokePatient_Username { get; } = "DexcomSmokeTest";
        public string SmokePatient_Displayname { get; } = "Dexcom Smoke Test";
        public string SmokePatient_Password { get; } = "Dexcom1";
        public string SmokePatient_Email { get; } = "noreply@rnd-dexcom.com";
        public string SmokePatient_Country { get; } = "US";
        public string SmokePatient_Language { get; } = "en-US";
        public Guid SmokePatient_AppId { get; } = CommonValues.AccountIdForDexcomCgmMobileApp_PROD;

        public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
        public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

        public int RsaKeyId { get; } = 101;

        public ApplicationRuntimeInfo AppleSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,7", };
        public ApplicationRuntimeInfo AppleUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,1", };
        public ApplicationRuntimeInfo AndroidSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_G5", AppNumber = "SW10940", AppVersion = "1.7.9.1", DeviceOsName = "Android", DeviceOsVersion = "6.0.1", DeviceManufacturer = "samsung", DeviceModel = "SM-S903VL", };
        public ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_G5", AppNumber = "SW10940", AppVersion = "0.0.0.0", DeviceOsName = "Android", DeviceOsVersion = "0.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G1000", };

        public bool CheckClocks { get; } = false; // Only do this when you have an extra "few minutes" rather than seconds.
        public bool CheckAppCompat { get; } = true;
        public bool CheckLegal { get; } = true;
        public bool CheckDeviceKey { get; } = true;
        public bool CheckDataPost { get; } = true;
        public bool CheckAdminCalls { get; } = true;
    }

    #endregion US ... LIFT_N_SHIFT from ScaleMatrix TO GCP

    #region US ... UAT

    public class SmokeTestContext_UAT_US : ISmokeTestContext
    {
        public bool IsProduction { get; } = true;

        public string ShareWebServices { get; } = "https://uat-share-us.dexcomdev.com/ShareWebServices/Services";
        public string ShareDataPostWebServices { get; } = "https://uat-share-us.dexcomdev.com/ShareDataPostWebServices/Services";
        public string AppCompatibilityWebServices { get; } = "https://uat-share-us.dexcomdev.com/AppCompatibilityWebServices/Services";
        public string LegalWebServices { get; } = "https://uat-share-us.dexcomdev.com/LegalWebServices/Services";

        public string ShareAdminWebServices { get; } = "https://uat-shareadmin-us.dexcomdev.com/ShareAdminWebServices/Services";
        public string ShareAdminWebServices_Login { get; } = "https://uat-shareadmin-us.dexcomdev.com/ShareAdminWebServices/Login";
        public string ShareAdminWebServices_User { get; } = "https://uat-shareadmin-us.dexcomdev.com/ShareAdminWebServices/User";
        public string AppCompatibilityAdminWebServices { get; } = "https://uat-shareadmin-us.dexcomdev.com/AppCompatibilityAdminWebServices/Services";
        public string ShareDataSyncWebServices { get; } = "https://uat-shareadmin-us.dexcomdev.com/ShareDataSyncWebServices/Services";
        public string ShareUAMWebServices { get; } = "https://uat-shareadmin-us.dexcomdev.com/ShareUAMWebServices/Services";

        public string StsIdentityService { get; } = "https://uat-uam-us.dexcomdev.com/identity/connect/token";

        public string StsClientId { get; } = "0D742E37-71F9-4363-8B25-57D09A05F712";
        public string SmokePatient_Username { get; } = "DexcomSmokeTest";
        public string SmokePatient_Displayname { get; } = "Dexcom Smoke Test";
        public string SmokePatient_Password { get; } = "Dexcom1";
        public string SmokePatient_Email { get; } = "noreply@rnd-dexcom.com";
        public string SmokePatient_Country { get; } = "US";
        public string SmokePatient_Language { get; } = "en-US";
        public Guid SmokePatient_AppId { get; } = CommonValues.AccountIdForDexcomCgmMobileApp_PROD;

        public string SmokeAdmin_Username { get; } = "DexcomSmokeTestAdmin";
        public string SmokeAdmin_Password { get; } = "Dexcom1Admin";

        public int RsaKeyId { get; } = 101;

        public ApplicationRuntimeInfo AppleSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,7", };
        public ApplicationRuntimeInfo AppleUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_IPAD", AppNumber = "SW10569", AppVersion = "3.0.1.5", DeviceOsName = "iPhone OS", DeviceOsVersion = "12.1.4", DeviceManufacturer = "Apple", DeviceModel = "iPad2,1", };
        public ApplicationRuntimeInfo AndroidSupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_VALID_G5", AppNumber = "SW10940", AppVersion = "1.7.9.1", DeviceOsName = "Android", DeviceOsVersion = "6.0.1", DeviceManufacturer = "samsung", DeviceModel = "SM-S903VL", };
        public ApplicationRuntimeInfo AndroidUnsupportedRuntime { get; } = new ApplicationRuntimeInfo() { AppName = "SMOKE_INVALID_G5", AppNumber = "SW10940", AppVersion = "0.0.0.0", DeviceOsName = "Android", DeviceOsVersion = "0.0.0", DeviceManufacturer = "samsung", DeviceModel = "SM-G1000", };

        public bool CheckClocks { get; } = false; // Only do this when you have an extra "few minutes" rather than seconds.
        public bool CheckAppCompat { get; } = true;
        public bool CheckLegal { get; } = true;
        public bool CheckDeviceKey { get; } = true;
        public bool CheckDataPost { get; } = true;
        public bool CheckAdminCalls { get; } = true;
    }

    #endregion

}
