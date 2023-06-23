using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Activities;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Http;
using System.Runtime.ExceptionServices;

namespace HmacTCP.HmacActivityBuild
{
    public class CustomHmacRequest : AsyncCodeActivity
    {
        
        [Category("Input")]
        [DisplayName("DataKey")]
        [Description("Input DataKey")]
        public InArgument<string> DataKey { get; set; }

        [Category("Input")]
        [DisplayName("UserID")]
        [Description("Input UserID")]
        public InArgument<string> UserID { get; set; }

        [Category("Input")]
        [DisplayName("AccessKeyID")]
        [Description("Input AccessKeyID")]
        public InArgument<string> AccessKeyID { get; set; }

        [Category("Input")]
        [DisplayName("SecretAccessKey")]
        [Description("Input SecretAccessKey")]
        public InArgument<string> SecretAccessKey { get; set; }

        [Category("Input")]
        [DisplayName("Method")]
        [Description("Input Method")]
        public InArgument<string> Method { get; set; }

        [Category("Input")]
        [DisplayName("Url")]
        [Description("Input Url")]
        public InArgument<string> Url { get; set; }

        [Category("Input")]
        [DisplayName("Data")]
        [Description("Input Data")]
        public InArgument<string> Data { get; set; }

        [Category("Input")]
        [DisplayName("FingerPrint")]
        [Description("Input FingerPrint")]
        public InArgument<string> FingerPrint { get; set; }

        [Category("Output")]
        [DisplayName("Result")]
        [Description("Result")]
        public OutArgument<string> Result { get; set; }

        [Category("Output")]
        [DisplayName("Status")]
        [Description("Status")]
        public OutArgument<int> Status { get; set; }

        static String createHmacAuthorization(String userId, String accessKey, String signature)
        {
            return "HMAC_1 " + accessKey + ":" + signature + ":" + userId;
        }

        static String createSignature(String signingBase, String secretKey)
        {
            byte[] k = Encoding.UTF8.GetBytes(secretKey);
            using (HMACSHA256 myhmacsha256 = new HMACSHA256(k))
            {
                Byte[] dataToHmac = Encoding.UTF8.GetBytes(signingBase);
                string signature = Convert.ToBase64String(myhmacsha256.ComputeHash(dataToHmac));
                return signature;
            }
        }

        static String createSigningBase(String url, String method, String xDapiDate, String data)
        {
            string baseStr = xDapiDate.ToLower() + method.ToLower();
            string path = url.Replace("https://", "");
            path = path.Substring(path.IndexOf("/"));
            baseStr += path.ToLower();
            if (method.ToUpper().Equals("POST"))
            {
                baseStr += data.ToLower();
            }
            return baseStr;
        }

        static String computeXDapiDate()
        {
            String isoDate = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            return isoDate;
        }

        static Dictionary<String, String> parseArgs(string[] args)
        {
            Dictionary<String, String> argMap = new Dictionary<String, String>();
            String key;
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (i % 2 == 0)
                {
                    key = args[i].Replace("-", "");
                    argMap[key] = args[i + 1];
                }
            }
            validateProgramArgs(argMap);
            return argMap;
        }
        static string[] expectedArgs = { "user", "accessKey", "secret", "url", "datakey", "method" };
        static void validateProgramArgs(Dictionary<String, String> programArgs)
        {
            for (int i = 0; i < expectedArgs.Length; i++)
            {
                if (!programArgs.ContainsKey(expectedArgs[i]))
                {
                    Console.WriteLine("Missing arg " + expectedArgs[i]);
                    Environment.Exit(0);
                }
            }
        }

        static String encodeUri(String url)
        {
            if (url.IndexOf("oql=") > -1)
            {
                Regex reg = new Regex("oql=(.*?)(?=&|$)");
                String param = reg.Match(url).Value;
                Console.WriteLine(param);
                url = url.Replace(param, Uri.EscapeDataString(param));
                url = url.Replace("oql%3D", "oql=");
            }
            return url;
        }

        protected  override  IAsyncResult BeginExecute(AsyncCodeActivityContext context, AsyncCallback callback, object state)
        {
            //this.context = context;
            //ExecuteAsync();
            //ExecuteAsync(context);

            var task = ExecuteAsync(context);
            var tcs = new TaskCompletionSource<HttpResponseMessage>(state);
            task.ContinueWith(t =>
            {
                if (t.IsFaulted)
                    tcs.TrySetException(t.Exception.InnerExceptions);
                else if (t.IsCanceled)
                    tcs.TrySetCanceled();
                else
                    tcs.TrySetResult(t.Result);

                if (callback != null)
                    callback(tcs.Task);
            });

            return tcs.Task;
        }

        protected override void EndExecute(AsyncCodeActivityContext context, IAsyncResult result)
        {
            //context.SetValue(Result, result);
            //context.SetValue(Status, status);
            var task = (Task<HttpResponseMessage>)result;
            try
            {
                var t =  task.Result;
                string s = t.Content.ReadAsStringAsync().Result;
                context.SetValue(Result,s );

                HttpStatusCode code = t.StatusCode;
                context.SetValue(Status,(int) code);
            }
            catch (Exception ex)
            {
                context.SetValue(Result, ex.Message.ToString());
                Console.WriteLine(HttpStatusCode.InternalServerError);
                context.SetValue(Status,500);
            }


            // No action required in this case
        }

        public  Task<HttpResponseMessage> ExecuteAsync(AsyncCodeActivityContext context)
        {
            {

                var datakey = context.GetValue(DataKey);
                var user = context.GetValue(UserID);
                var accessKey = context.GetValue(AccessKeyID);
                var secretKey = context.GetValue(SecretAccessKey);
                var method = context.GetValue(Method);
                var apiRequestUri = context.GetValue(Url);
                var fingerprint = context.GetValue(FingerPrint);
                var data = context.GetValue(Data);

                
                //string result;
                //int status;

                try
                {
                    string[] args = { "user", user, "accessKey", accessKey, "secret", secretKey, "url", apiRequestUri, "datakey", datakey, "method", method, "data", data };

                    Dictionary<String, String> programArguments = parseArgs(args);
                    Console.WriteLine("URL - " + apiRequestUri);
                    String payload = null;
                    if (method.ToUpper().Equals("POST"))
                    {
                        if (programArguments.ContainsKey("data"))
                        {
                            payload = programArguments["data"];
                        }
                        else
                        {
                            Console.WriteLine("POST method requires argument -data");
                            Environment.Exit(0);
                        }
                    }

                    apiRequestUri = encodeUri(apiRequestUri);

                    String xDapiDate = computeXDapiDate();
                    String signingBase = createSigningBase(apiRequestUri, method, xDapiDate, payload);
                    String signature = createSignature(signingBase, secretKey);
                    String hmacAuthorization = createHmacAuthorization(user, accessKey, signature);
                    Console.WriteLine("SIGNING BASE : {0}", signingBase);
                    Console.WriteLine("Authorization Signature : {0}", signature);
                    Console.WriteLine("Hmac Authorization : {0}", hmacAuthorization);

                    ServicePointManager.Expect100Continue = true;
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                    HttpClient client = new HttpClient();
                    client.DefaultRequestHeaders.Add("Accept", "application/json");
                    client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");
                    client.DefaultRequestHeaders.Add("Authorization", hmacAuthorization);
                    client.DefaultRequestHeaders.Add("ContentType", "application/json; charset=UTF-8");
                    client.DefaultRequestHeaders.Add("datakey", datakey);
                    client.DefaultRequestHeaders.Add("x-dapi-date", xDapiDate);
                    if (method.ToUpper().Equals("POST"))
                    {
                        Console.WriteLine("METHOD POST");
                        Console.WriteLine("START -- DefaultRequestHeaders");
                        client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", "\"" + fingerprint + "\"");
                        Console.WriteLine("DefaultRequestHeaders------" + client.DefaultRequestHeaders);
                        HttpContent content = new StringContent(data, Encoding.UTF8, "application/json");
                        return client.PostAsync(apiRequestUri, content);
                        //HttpResponseMessage response =  client.PostAsync(apiRequestUri, content);
                        //HttpStatusCode statusCode = response.StatusCode;
                        //string resultJSON = await response.Content.ReadAsStringAsync();
                        //result = resultJSON;
                        //Console.WriteLine("resultJSON POST------" + resultJSON);
                        //status = (int)statusCode;
                        //Console.WriteLine("statusCode POST------" + statusCode);
                    }
                    else
                    {
                        return client.GetAsync(apiRequestUri);
                        //Console.WriteLine("METHOD GET");
                        //HttpResponseMessage response = await client.GetAsync(apiRequestUri);
                        //string resultJSON = await response.Content.ReadAsStringAsync();
                        //Console.WriteLine("resultJSON GET------" + resultJSON);
                        //HttpStatusCode statusCode = response.StatusCode;
                        //result = resultJSON;
                        //status = (int)statusCode;
                        //Console.WriteLine("statusCode POST------" + statusCode);
                    }

                    //context.SetValue(Result, result);
                    //context.SetValue(Status, status);
                    //return Task.FromResult<Action<AsyncCodeActivityContext>>(null);
                }
                catch (Exception ex)
                {
                    // Handle any exceptions and set the output arguments accordingly
                    ////result = ex.Message;
                    ////status = 500;
                    //Result.Set(context, ex.Message);
                    //Status.Set(context, 500);
                    throw new Exception(ex.Message);
                    
                }
            }
        }
    }
}
