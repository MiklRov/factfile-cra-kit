plugins {
    id("com.android.library")
}

dependencies {
    // inter-module dependency — must NOT appear in the SBOM as an external component
    implementation(project(":mod-b"))
    implementation(libs.androidx.core.ktx)
}
