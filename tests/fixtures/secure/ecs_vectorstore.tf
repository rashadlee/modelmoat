// VEC-003 near misses: each of these looks like a publicly reachable
// self-hosted vector database on ECS but must stay silent.

// A real Qdrant image, but assign_public_ip is not set (defaults to false).
resource "aws_ecs_task_definition" "qdrant_private" {
  family                   = "qdrant-private"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                       = "512"
  memory                    = "1024"

  container_definitions = jsonencode([
    {
      name  = "qdrant"
      image = "qdrant/qdrant:v1.9.0"
      portMappings = [{ containerPort = 6333 }]
    }
  ])
}

resource "aws_ecs_service" "qdrant_private" {
  name            = "qdrant-private"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.qdrant_private.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets         = ["subnet-11111111"]
    security_groups = ["sg-11111111"]
  }
}

// A real Weaviate image with assign_public_ip explicitly false.
resource "aws_ecs_task_definition" "weaviate_private" {
  family                   = "weaviate-private"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                       = "1024"
  memory                    = "2048"

  container_definitions = jsonencode([
    {
      name  = "weaviate"
      image = "cr.weaviate.io/semitechnologies/weaviate:1.25.0"
      portMappings = [{ containerPort = 8080 }]
    }
  ])
}

resource "aws_ecs_service" "weaviate_private" {
  name            = "weaviate-private"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.weaviate_private.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    assign_public_ip = false
  }
}

// A real Milvus image, public IP assigned, but launch_type is EC2 - the ECS
// API does not honor assign_public_ip outside Fargate, so this must not fire.
resource "aws_ecs_task_definition" "milvus_ec2" {
  family        = "milvus-ec2"
  network_mode  = "awsvpc"
  cpu           = "2048"
  memory        = "4096"

  container_definitions = jsonencode([
    {
      name  = "milvus-standalone"
      image = "milvusdb/milvus:v2.4.5"
      portMappings = [{ containerPort = 19530 }]
    }
  ])
}

resource "aws_ecs_service" "milvus_ec2" {
  name            = "milvus-ec2"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.milvus_ec2.arn
  launch_type     = "EC2"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    assign_public_ip = true
  }
}

// A private ECR image with a custom name. modelmoat cannot prove which
// engine this is, so this stays silent even with a public IP assigned - the
// same accepted blind spot PIN-001 and VEC-002 already document.
resource "aws_ecs_task_definition" "internal_vectordb" {
  family                   = "internal-vectordb"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                       = "1024"
  memory                    = "2048"

  container_definitions = jsonencode([
    {
      name  = "vectordb"
      image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/internal-vectordb:latest"
      portMappings = [{ containerPort = 6333 }]
    }
  ])
}

resource "aws_ecs_service" "internal_vectordb" {
  name            = "internal-vectordb"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.internal_vectordb.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    assign_public_ip = true
  }
}

// Whole path matching: a lookalike repository name is not qdrant/qdrant.
resource "aws_ecs_task_definition" "qdrant_lookalike" {
  family                   = "qdrant-lookalike"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                       = "512"
  memory                    = "1024"

  container_definitions = jsonencode([
    {
      name  = "vectordb"
      image = "acme/myqdrant-fork:latest"
      portMappings = [{ containerPort = 6333 }]
    }
  ])
}

resource "aws_ecs_service" "qdrant_lookalike" {
  name            = "qdrant-lookalike"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.qdrant_lookalike.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    assign_public_ip = true
  }
}

// An unrelated ECS service with a public IP. Not a vector database at all,
// so out of scope regardless of network configuration.
resource "aws_ecs_task_definition" "web_frontend" {
  family                   = "web-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                       = "512"
  memory                    = "1024"

  container_definitions = jsonencode([
    {
      name  = "frontend"
      image = "nginx:1.27"
      portMappings = [{ containerPort = 80 }]
    }
  ])
}

resource "aws_ecs_service" "web_frontend" {
  name            = "web-frontend"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.web_frontend.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    assign_public_ip = true
  }
}
