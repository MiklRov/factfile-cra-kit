// Root build script: plugins only, no dependencies block — mirrors a real
// multi-module Android project (see android_family/build.gradle.kts).
plugins {
    id("com.android.application") apply false
}
