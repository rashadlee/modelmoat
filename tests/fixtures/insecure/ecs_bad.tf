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
# EC2 launch type: bridge/host networking isn't verified by this check, so
# this must stay silent even though the same Bedrock signal is present.
resource "aws_ecs_task_definition" "ec2_agent" {
  family                   = "ec2-agent"
  requires_compatibilities = ["EC2"]
  container_definitions = jsonencode([
    {
      name  = "agent"
      image = "ec2-agent:latest"
      environment = [
        { name = "BEDROCK_MODEL_ID", value = "anthropic.claude-3-sonnet" }
      ]
    }
  ])
}
resource "aws_ecs_service" "ec2_agent" {
  name            = "ec2-agent"
  cluster         = "ai-cluster"
  task_definition = aws_ecs_task_definition.ec2_agent.arn
  launch_type     = "EC2"
  desired_count   = 1
}
