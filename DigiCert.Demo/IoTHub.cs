using Microsoft.Azure.Devices.Client;
using Microsoft.Azure.Devices.Client.Exceptions;
using Microsoft.Azure.Devices.Shared;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigiCert.Demo
{
    public class IoTHub
    {
        public event EventHandler<string> MessageHandler;
        protected ConcurrentQueue<Message> _pendingMessages = new ConcurrentQueue<Message>();
        protected DeviceClient _deviceClient;
        protected string _deviceName;
        protected int _errorCount;
        protected SemaphoreSlim _deviceClientSemaphore = new SemaphoreSlim(1);
        private IConfigurationRoot _configuration;
        private X509Certificate2 _certificate;
        private bool running = false;
        public bool Initialized = false;

        public Twin Twin { get; set; }
        public delegate void DeviceOperation(DeviceClient client);

        public IoTHub()
        {

        }

        public IoTHub(EventHandler<string> message)
        {
            MessageHandler += message;
        }

        public async Task<IoTHub> InitAsync(IConfigurationRoot configuration, X509Certificate2 certificate)
        {
            try
            {
                _configuration = configuration;
                _certificate = certificate;
                if (await tryRefreshTokenAsync())
                    return this;
                return null;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public async Task SendMessage(string messageString, string routing = "status")
        {
            var message = new Message(Encoding.ASCII.GetBytes(messageString));
            message.Properties.Add("routing", routing);
            _pendingMessages.Enqueue(message);

            try
            {
                await sendQueuedMessages();
            }
            catch (Exception e)
            {
                handleMessage("Error logging data to Azure:\n" + e.Message);
            }
        }

        public async Task StartReceiving()
        {
            running = true;
            while (running)
            {
                Message receivedMessage;
                try
                {
                    await _deviceClientSemaphore.WaitAsync();
                    receivedMessage = await _deviceClient.ReceiveAsync();
                    _deviceClientSemaphore.Release();
                    if (receivedMessage == null)
                    {
                        continue;
                    }
                    var dataString = Encoding.ASCII.GetString(receivedMessage.GetBytes());
                    handleMessage("Recieved Message:\n" + dataString);
                }
                catch (Exception e)
                {
                    handleMessage("Error receiving messsage\n" + e);
                }
                finally
                {
                    _deviceClientSemaphore.Release();
                }
            }
        }

        public void SetMethod(string name, MethodCallback method)
        {
            _deviceClient.SetMethodHandlerAsync(name, method, null).Wait();
        }

        public async Task UpdateReportedPropertiesAsync(TwinCollection properties)
        {
            await doDeviceOperation(client =>
            {
                for (int i = 0; i < 10; i++)
                    try
                    {
                        client.UpdateReportedPropertiesAsync(properties).Wait();
                        break;
                    }
                    catch (Exception e)
                    {
                        handleMessage($"Failed to save settings to Azure: {e.Message}");
                    }
            });
        }

        public async Task UploadToBlobAsync(string fileLocation, string fileName = null)
        {
            if (fileName == null)
                fileName = fileLocation;
            if (!File.Exists(fileName))
            {
                handleMessage($"Could not find file {fileName} to upload");
                return;
            }
            try
            {
                handleMessage($"Uploading file: {fileName}");
                var watch = Stopwatch.StartNew();

                await doDeviceOperation(async (DeviceClient client) =>
                {
                    using (var sourceData = File.OpenRead(fileLocation))
                    {
                        await client.UploadToBlobAsync(fileName, sourceData);
                    }
                });

                watch.Stop();
                handleMessage($"Time to upload file: {watch.ElapsedMilliseconds}ms\n");
            }
            catch (Exception e)
            {
                handleMessage($"Could not upload file {fileName}\n" + e.ToString());
            }
        }

        public Task<Twin> GetTwinAsync()
        {
            return _deviceClient.GetTwinAsync();
        }

        public async Task UploadStreamAsync(string name, Stream source)
        {
            await _deviceClientSemaphore.WaitAsync();
            if (source != null)
                await _deviceClient.UploadToBlobAsync(name, source);
            _deviceClientSemaphore.Release();
        }

        public async void StopReceiving()
        {
            running = false;
            await _deviceClientSemaphore.WaitAsync();
            _deviceClient.SetMethodHandlerAsync("Reboot", null, null).Wait();
            _deviceClient.CloseAsync().Wait();
            _deviceClientSemaphore.Release();
        }

        protected async Task<bool> tryRefreshTokenAsync()
        {
            try
            {
                await _deviceClientSemaphore.WaitAsync();
                _deviceName = _certificate.GetNameInfo(X509NameType.DnsName, false);
                var auth = new DeviceAuthenticationWithX509Certificate(_deviceName, _certificate);
                _deviceClient = DeviceClient.Create(_configuration["HostName"], auth, TransportType.Mqtt);
                await _deviceClient.OpenAsync().ConfigureAwait(false);
                Twin = await _deviceClient.GetTwinAsync().ConfigureAwait(false);
                _deviceClientSemaphore.Release();
                handleMessage("Connection established");
                Initialized = true;
                return true;
            }
            catch (Exception e)
            {
                handleMessage("Exception connecting to Azure:\n" + e.Message);
                _deviceClient = null;
                return false;
            }
        }

        protected async Task sendQueuedMessages()
        {
            if (_deviceClient == null && !await tryRefreshTokenAsync())
            {
                // No connection and failed to reconnect.
                return;
            }

            List<Message> messages = new List<Message>();
            while (_pendingMessages.TryDequeue(out Message message))
            {
                messages.Add(message);
            }
            if (messages.Any())
                try
                {
                    await doDeviceOperation(client =>
                    {
                        try
                        {
                            client.SendEventBatchAsync(messages).Wait();
                            handleMessage("Sending messages");
                            _errorCount = 0;
                        }
                        catch (UnauthorizedException e)
                        {
                            handleMessage("Azure UnauthorizedException, refreshing SAS token\n"+e.ToString());
                            _errorCount = 0;
                            var task = tryRefreshTokenAsync();
                            task.Wait();
                            if (!task.Result)
                            {
                                throw new UnauthorizedException("Failed to refresh Azure connection");
                            }
                        }
                        catch (Exception e)
                        {
                            if (!running)
                            {
                                handleMessage($"Azure error due to reboot: {e.Message}.");
                                return;
                            }
                            if (e.Message == "One or more errors occurred. (The operation completed successfully)")
                            {
                                handleMessage($"Ignoring Azure error: {e.Message}.");
                                _errorCount = 0;
                                return;
                            }
                            _errorCount++;
                            handleMessage($"Azure error sending message: {e.Message}.");
                            foreach (var message in messages)
                            {
                                _pendingMessages.Enqueue(message);
                            }
                            if (_errorCount > 5)
                            {
                                handleMessage("Too many failed Azure operations, refreshing connection.\n"+ e.ToString());
                                var task = tryRefreshTokenAsync();
                                task.Wait();
                                if (!task.Result)
                                {
                                    throw new Exception($"Failed to refresh Azure connection after error {e.Message}.", e);
                                }
                            }
                        }
                    });
                    if (running)
                        await sendQueuedMessages();
                }
                catch (Exception e)
                {
                    // Re-enqueue failed events.
                    foreach (var message in messages)
                    {
                        _pendingMessages.Enqueue(message);
                    }
                    throw new Exception("SendEventBatchAsync failed: " + e.Message, e);
                }
        }

        protected async Task doDeviceOperation(DeviceOperation operation)
        {
            await _deviceClientSemaphore.WaitAsync();
            try
            {
                operation(_deviceClient);
                _errorCount = 0;
            }
            catch (UnauthorizedException)
            {
                handleMessage("Azure UnauthorizedException, refreshing SAS token");
                if (!await tryRefreshTokenAsync())
                {
                    throw new UnauthorizedException("Failed to refresh Azure connection");
                }
                operation(_deviceClient);
            }
            catch (Exception e)
            {
                handleMessage($"Azure error: {e.Message}.");
                _errorCount++;
                if (_errorCount > 5)
                {
                    handleMessage("Too many failed Azure operations, refreshing connection.");
                    if (!await tryRefreshTokenAsync())
                    {
                        throw new Exception($"Failed to refresh Azure connection after error {e.Message}.", e);
                    }
                    operation(_deviceClient);
                    _errorCount = 0;
                }
                else
                {
                    throw new Exception($"Azure operation failed: {e.Message}.", e);
                }
            }
            finally
            {
                _deviceClientSemaphore.Release();
            }
        }

        private void handleMessage(string message)
        {
            MessageHandler?.Invoke(this, message);
        }
    }
}
