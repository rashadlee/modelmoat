"""Check registry."""

from .apigateway import APIGatewayAIProxyAuthCheck
from .apigateway_policy import APIGatewayPublicResourcePolicyCheck
from .azure_ai_search import AzureAISearchCheck
from .azure_machine_learning import AzureMachineLearningNetworkCheck
from .azure_openai import AzureOpenAINetworkCheck
from .azure_openai_auth import AzureOpenAILocalAuthCheck
from .bedrock_agentcore import BedrockAgentCoreGatewayCheck
from .bedrock_agentcore_debug import BedrockAgentCoreDebugExceptionsCheck
from .datastores import VectorDataStoreCheck
from .ecs_vectorstore import ECSVectorStoreReachabilityCheck
from .iam import AIServiceIAMCheck
from .model_registry import ModelPackageGroupPolicyCheck
from .network import AIVPCEndpointCheck
from .pinecone import PineconeOrgRoleCheck
from .s3 import ModelArtifactBucketCheck
from .sagemaker import SageMakerNetworkCheck
from .vertex_ai import VertexAIReasoningEngineCheck
from .weaviate import WeaviateAnonymousAccessCheck

ALL_CHECKS = [
    SageMakerNetworkCheck(),
    AIServiceIAMCheck(),
    ModelArtifactBucketCheck(),
    AIVPCEndpointCheck(),
    VectorDataStoreCheck(),
    WeaviateAnonymousAccessCheck(),
    ECSVectorStoreReachabilityCheck(),
    PineconeOrgRoleCheck(),
    AzureOpenAINetworkCheck(),
    BedrockAgentCoreGatewayCheck(),
    VertexAIReasoningEngineCheck(),
    APIGatewayAIProxyAuthCheck(),
    ModelPackageGroupPolicyCheck(),
    AzureOpenAILocalAuthCheck(),
    BedrockAgentCoreDebugExceptionsCheck(),
    APIGatewayPublicResourcePolicyCheck(),
    AzureMachineLearningNetworkCheck(),
    AzureAISearchCheck(),
]
