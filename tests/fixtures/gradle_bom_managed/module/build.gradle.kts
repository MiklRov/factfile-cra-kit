plugins {
    id("com.android.library")
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
}
