resource "aws_iam_role" "fargate_task" {
  name = "fargate-agent-task-role"
}
resource "aws_ecs_task_definition" "fargate_agent" {
  family                   = "fargate-agent"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.fargate_task.arn
  container_definitions = jsonencode([
    {
      name  = "agent"
      image = "fargate-agent:latest"
      environment = [
        { name = "BEDROCK_MODEL_ID", value = "anthropic.claude-3-sonnet" }
      ]
    }
  ])
}
# Signals call Bedrock and runs on Fargate, but network.tf's bedrock_runtime
# interface endpoint already covers it - proves endpoint matching applies
# across resource types, not just Lambda.
resource "aws_ecs_service" "fargate_agent" {
  name            = "fargate-agent"
  cluster         = "ai-cluster"
  task_definition = aws_ecs_task_definition.fargate_agent.arn
  launch_type     = "FARGATE"
  desired_count   = 1
  network_configuration {
    subnets = [aws_subnet.private_a.id]
  }
}
