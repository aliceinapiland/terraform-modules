terraform {
  backend "gcs" {
    bucket  = "vr-sample-apigee-tf-project-1-tf"
    prefix  = "terraform/state"
  }
}
