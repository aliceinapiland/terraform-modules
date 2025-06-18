terraform {
  backend "gcs" {
    bucket  = "vr-16thjune2025-apigeex-tf-prj-tf"
    prefix  = "terraform/state"
  }
}
