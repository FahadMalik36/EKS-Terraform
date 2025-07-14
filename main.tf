provider "aws" {
  region = "ap-south-1"
}

variable "ssh_key_name" {
  description = "SSH key pair name for node access"
  default     = "DevOps-Shack" # Change this or override via TF_VAR_ssh_key_name
}

# 1. Solution: Create the key pair if it doesn't exist
resource "aws_key_pair" "devopsshack" {
  key_name   = var.ssh_key_name
  public_key = file("~/.ssh/id_rsa.pub") # Replace with your public key path
}

# VPC Configuration (unchanged)
resource "aws_vpc" "devopsshack_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "devopsshack-vpc"
  }
}

resource "aws_subnet" "devopsshack_subnet" {
  count = 2
  vpc_id                  = aws_vpc.devopsshack_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.devopsshack_vpc.cidr_block, 8, count.index)
  availability_zone       = element(["ap-south-1a", "ap-south-1b"], count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "devopsshack-subnet-${count.index}"
  }
}

resource "aws_internet_gateway" "devopsshack_igw" {
  vpc_id = aws_vpc.devopsshack_vpc.id
  tags = {
    Name = "devopsshack-igw"
  }
}

resource "aws_route_table" "devopsshack_route_table" {
  vpc_id = aws_vpc.devopsshack_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.devopsshack_igw.id
  }
  tags = {
    Name = "devopsshack-route-table"
  }
}

resource "aws_route_table_association" "a" {
  count          = 2
  subnet_id      = aws_subnet.devopsshack_subnet[count.index].id
  route_table_id = aws_route_table.devopsshack_route_table.id
}

# Security Groups with improved rules
resource "aws_security_group" "devopsshack_cluster_sg" {
  name_prefix = "devopsshack-cluster-sg-"
  vpc_id      = aws_vpc.devopsshack_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "devopsshack-cluster-sg"
  }
}

resource "aws_security_group" "devopsshack_node_sg" {
  name_prefix = "devopsshack-node-sg-"
  vpc_id      = aws_vpc.devopsshack_vpc.id

  ingress {
    description = "Allow nodes to communicate with each other"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "Allow SSH access (optional)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Restrict this in production!
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "devopsshack-node-sg"
  }
}

# IAM Roles (unchanged)
resource "aws_iam_role" "devopsshack_cluster_role" {
  name = "devopsshack-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "devopsshack_cluster_role_policy" {
  role       = aws_iam_role.devopsshack_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "devopsshack_node_group_role" {
  name = "devopsshack-node-group-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "devopsshack_node_group_role_policy" {
  role       = aws_iam_role.devopsshack_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "devopsshack_node_group_cni_policy" {
  role       = aws_iam_role.devopsshack_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "devopsshack_node_group_registry_policy" {
  role       = aws_iam_role.devopsshack_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# EKS Cluster with added logging
resource "aws_eks_cluster" "devopsshack" {
  name     = "devopsshack-cluster"
  role_arn = aws_iam_role.devopsshack_cluster_role.arn
  version  = "1.28" # Specify your desired Kubernetes version

  vpc_config {
    subnet_ids         = aws_subnet.devopsshack_subnet[*].id
    security_group_ids = [aws_security_group.devopsshack_cluster_sg.id]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

# EKS Node Group with fixed key pair reference
resource "aws_eks_node_group" "devopsshack" {
  cluster_name    = aws_eks_cluster.devopsshack.name
  node_group_name = "devopsshack-node-group"
  node_role_arn   = aws_iam_role.devopsshack_node_group_role.arn
  subnet_ids      = aws_subnet.devopsshack_subnet[*].id
  ami_type        = "AL2_x86_64" # Explicitly set AMI type
  capacity_type   = "ON_DEMAND"  # or "SPOT" for cost savings

  scaling_config {
    desired_size = 2 # Reduced from 3 for cost savings
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"] # Better than t2.medium (bursting)

  remote_access {
    ec2_ssh_key               = aws_key_pair.devopsshack.key_name # Reference the created key pair
    source_security_group_ids = [aws_security_group.devopsshack_node_sg.id]
  }

  # Ensure nodes are created after cluster is ready
  depends_on = [
    aws_eks_cluster.devopsshack,
    aws_key_pair.devopsshack
  ]

  lifecycle {
    create_before_destroy = true
  }
}

# Addon: CoreDNS (recommended)
resource "aws_eks_addon" "coredns" {
  cluster_name      = aws_eks_cluster.devopsshack.name
  addon_name        = "coredns"
  addon_version     = "v1.10.1-eksbuild.6" # Update to latest
  resolve_conflicts = "OVERWRITE"
}
