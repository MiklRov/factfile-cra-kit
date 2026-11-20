plugins {
    id("org.jetbrains.kotlin.jvm") version "2.0.0"
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    testImplementation("junit:junit:4.13.2")
}
