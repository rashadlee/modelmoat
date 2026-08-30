// VEC-003: self-hosted vector databases on ECS Fargate with a public IP.
// Each of the three images modelmoat can identify by name, each on its own
// service so the finding's resource_name distinguishes them.

resource "aws_ecs_task_definition" "qdrant" {
  family                   = "qdrant"
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

resource "aws_ecs_service" "qdrant" {
  name            = "qdrant"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.qdrant.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    security_groups  = ["sg-11111111"]
    assign_public_ip = true
  }
}

resource "aws_ecs_task_definition" "weaviate" {
  family                   = "weaviate"
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

resource "aws_ecs_service" "weaviate" {
  name            = "weaviate"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.weaviate.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    assign_public_ip = true
  }
}

resource "aws_ecs_task_definition" "milvus" {
  family                   = "milvus"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                       = "2048"
  memory                    = "4096"

  container_definitions = jsonencode([
    {
      name  = "milvus-standalone"
      image = "milvusdb/milvus:v2.4.5"
      portMappings = [{ containerPort = 19530 }]
    }
  ])
}

resource "aws_ecs_service" "milvus" {
  name            = "milvus"
  cluster         = "rag-cluster"
  task_definition = aws_ecs_task_definition.milvus.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = ["subnet-11111111"]
    assign_public_ip = true
  }
}
