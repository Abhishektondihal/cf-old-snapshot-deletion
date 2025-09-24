variable "project_id" {}
variable "region" { default = "us-central1" }
variable "function_source_bucket" {}
variable "source_object" {}
variable "report_bucket" {}
variable "days_threshold" { default = 1 }
variable "org_id" { default = "" }
variable "schedule_cron" { default = "0 3 * * *" }
variable "time_zone" { default = "Etc/UTC" }
