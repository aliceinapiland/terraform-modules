terraform {
  backend "gcs" {
    bucket  = "vr-cat-tf-demo-tf"
    prefix  = "terraform/state"
  }
}
