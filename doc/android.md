# Signing Android packages

Android presently has two types of signature. Version 1 signatures are simply standard JAR signatures. Version 2 is Android-specific and can be applied to a V1 signed package. In order to prevent a downgrade attack by stripping the V2 signature, an additional header is inserted into the V1 signature which will indicate to V2-capable verifiers that a V2 signature must be present.

To create a dual-version APK signature with relic, first create the JAR signature then the APK signature:

    relic sign -k mykey -f mypackage.apk -T jar --apk-v2-present
    relic sign -k mykey -f mypackage.apk

For more information on Android package signing, see: https://source.android.com/security/apksigning/v2
