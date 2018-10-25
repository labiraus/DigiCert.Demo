﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     //
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace DigiCert.Demo.HealthCheck
{
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://schemas.pki.symantec.com/pkiservices/healthcheck", ConfigurationName="DigiCert.Demo.HealthCheck.HealthcheckServiceOperations")]
    public interface HealthcheckServiceOperations
    {
        
        [System.ServiceModel.OperationContractAttribute(Action="http://schemas.pki.symantec.com/pkiservices/healthcheck/getStatus", ReplyAction="*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        System.Threading.Tasks.Task<DigiCert.Demo.HealthCheck.getStatusResponse> getStatusAsync(DigiCert.Demo.HealthCheck.getStatusRequest request);
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://schemas.pki.symantec.com/pkiservices/healthcheck")]
    public partial class GetStatusRequestMessageType
    {
        
        private string versionField;
        
        private string clientTransactionIDField;
        
        private OperationType operationTypeField;
        
        private string profileOidField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string version
        {
            get
            {
                return this.versionField;
            }
            set
            {
                this.versionField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string clientTransactionID
        {
            get
            {
                return this.clientTransactionIDField;
            }
            set
            {
                this.clientTransactionIDField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public OperationType operationType
        {
            get
            {
                return this.operationTypeField;
            }
            set
            {
                this.operationTypeField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string profileOid
        {
            get
            {
                return this.profileOidField;
            }
            set
            {
                this.profileOidField = value;
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://schemas.pki.symantec.com/pkiservices/healthcheck")]
    public enum OperationType
    {
        
        /// <remarks/>
        ENROLL,
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://schemas.pki.symantec.com/pkiservices/healthcheck")]
    public partial class GetStatusResponseMessageType
    {
        
        private string versionField;
        
        private string clientTransactionIDField;
        
        private string serverTransactionIDField;
        
        private StatusCode statusCodeField;
        
        private string statusMessageField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string version
        {
            get
            {
                return this.versionField;
            }
            set
            {
                this.versionField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string clientTransactionID
        {
            get
            {
                return this.clientTransactionIDField;
            }
            set
            {
                this.clientTransactionIDField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string serverTransactionID
        {
            get
            {
                return this.serverTransactionIDField;
            }
            set
            {
                this.serverTransactionIDField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public StatusCode statusCode
        {
            get
            {
                return this.statusCodeField;
            }
            set
            {
                this.statusCodeField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string statusMessage
        {
            get
            {
                return this.statusMessageField;
            }
            set
            {
                this.statusMessageField = value;
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://schemas.pki.symantec.com/pkiservices/healthcheck")]
    public enum StatusCode
    {
        
        /// <remarks/>
        UP,
        
        /// <remarks/>
        DOWN,
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class getStatusRequest
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://schemas.pki.symantec.com/pkiservices/healthcheck", Order=0)]
        public DigiCert.Demo.HealthCheck.GetStatusRequestMessageType getStatusRequestMessage;
        
        public getStatusRequest()
        {
        }
        
        public getStatusRequest(DigiCert.Demo.HealthCheck.GetStatusRequestMessageType getStatusRequestMessage)
        {
            this.getStatusRequestMessage = getStatusRequestMessage;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class getStatusResponse
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://schemas.pki.symantec.com/pkiservices/healthcheck", Order=0)]
        public DigiCert.Demo.HealthCheck.GetStatusResponseMessageType getStatusResponseMessage;
        
        public getStatusResponse()
        {
        }
        
        public getStatusResponse(DigiCert.Demo.HealthCheck.GetStatusResponseMessageType getStatusResponseMessage)
        {
            this.getStatusResponseMessage = getStatusResponseMessage;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    public interface HealthcheckServiceOperationsChannel : DigiCert.Demo.HealthCheck.HealthcheckServiceOperations, System.ServiceModel.IClientChannel
    {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.0")]
    public partial class HealthcheckServiceOperationsClient : System.ServiceModel.ClientBase<DigiCert.Demo.HealthCheck.HealthcheckServiceOperations>, DigiCert.Demo.HealthCheck.HealthcheckServiceOperations
    {
        
    /// <summary>
    /// Implement this partial method to configure the service endpoint.
    /// </summary>
    /// <param name="serviceEndpoint">The endpoint to configure</param>
    /// <param name="clientCredentials">The client credentials</param>
    static partial void ConfigureEndpoint(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Description.ClientCredentials clientCredentials);
        
        public HealthcheckServiceOperationsClient() : 
                base(HealthcheckServiceOperationsClient.GetDefaultBinding(), HealthcheckServiceOperationsClient.GetDefaultEndpointAddress())
        {
            this.Endpoint.Name = EndpointConfiguration.HealthcheckServiceSOAP.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public HealthcheckServiceOperationsClient(EndpointConfiguration endpointConfiguration) : 
                base(HealthcheckServiceOperationsClient.GetBindingForEndpoint(endpointConfiguration), HealthcheckServiceOperationsClient.GetEndpointAddress(endpointConfiguration))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public HealthcheckServiceOperationsClient(EndpointConfiguration endpointConfiguration, string remoteAddress) : 
                base(HealthcheckServiceOperationsClient.GetBindingForEndpoint(endpointConfiguration), new System.ServiceModel.EndpointAddress(remoteAddress))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public HealthcheckServiceOperationsClient(EndpointConfiguration endpointConfiguration, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(HealthcheckServiceOperationsClient.GetBindingForEndpoint(endpointConfiguration), remoteAddress)
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public HealthcheckServiceOperationsClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress)
        {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<DigiCert.Demo.HealthCheck.getStatusResponse> DigiCert.Demo.HealthCheck.HealthcheckServiceOperations.getStatusAsync(DigiCert.Demo.HealthCheck.getStatusRequest request)
        {
            return base.Channel.getStatusAsync(request);
        }
        
        public System.Threading.Tasks.Task<DigiCert.Demo.HealthCheck.getStatusResponse> getStatusAsync(DigiCert.Demo.HealthCheck.GetStatusRequestMessageType getStatusRequestMessage)
        {
            DigiCert.Demo.HealthCheck.getStatusRequest inValue = new DigiCert.Demo.HealthCheck.getStatusRequest();
            inValue.getStatusRequestMessage = getStatusRequestMessage;
            return ((DigiCert.Demo.HealthCheck.HealthcheckServiceOperations)(this)).getStatusAsync(inValue);
        }
        
        public virtual System.Threading.Tasks.Task OpenAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginOpen(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndOpen));
        }
        
        public virtual System.Threading.Tasks.Task CloseAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginClose(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndClose));
        }
        
        private static System.ServiceModel.Channels.Binding GetBindingForEndpoint(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.HealthcheckServiceSOAP))
            {
                System.ServiceModel.BasicHttpBinding result = new System.ServiceModel.BasicHttpBinding();
                result.MaxBufferSize = int.MaxValue;
                result.ReaderQuotas = System.Xml.XmlDictionaryReaderQuotas.Max;
                result.MaxReceivedMessageSize = int.MaxValue;
                result.AllowCookies = true;
                result.Security.Mode = System.ServiceModel.BasicHttpSecurityMode.Transport;
                return result;
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        private static System.ServiceModel.EndpointAddress GetEndpointAddress(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.HealthcheckServiceSOAP))
            {
                return new System.ServiceModel.EndpointAddress("https://pki-ws.symauth.com/pki-ws/healthcheckService");
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        private static System.ServiceModel.Channels.Binding GetDefaultBinding()
        {
            return HealthcheckServiceOperationsClient.GetBindingForEndpoint(EndpointConfiguration.HealthcheckServiceSOAP);
        }
        
        private static System.ServiceModel.EndpointAddress GetDefaultEndpointAddress()
        {
            return HealthcheckServiceOperationsClient.GetEndpointAddress(EndpointConfiguration.HealthcheckServiceSOAP);
        }
        
        public enum EndpointConfiguration
        {
            
            HealthcheckServiceSOAP,
        }
    }
}
