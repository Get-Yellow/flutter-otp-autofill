package ru.surfstudio.otp_autofill

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

private const val HASH_TYPE = "SHA-256"
private const val NUM_HASHED_BYTES = 9
private const val NUM_BASE64_CHAR = 11

/// From Google Example App
// https://github.com/googlearchive/android-credentials/blob/master/sms-verification/android/app/src/main/java/com/google/samples/smartlock/sms_verify/AppSignatureHelper.java
class AppSignatureHelper(context: Context) : ContextWrapper(context) {

    fun getAppSignatures(): List<String> {
        return try {
            val packageName = packageName
            val packageManager = packageManager
            // Get package info including signatures
            val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            // Safely handle null signatures by returning an empty list if null
            val signatures = packageInfo.signatures ?: return emptyList()
            signatures.mapNotNull { signature ->
                hash(packageName, signature.toCharsString())
            }
        } catch (e: PackageManager.NameNotFoundException) {
            emptyList()
        }
    }

    private fun hash(packageName: String, signature: String): String? {
        val appInfo = "$packageName $signature"
        return try {
            val messageDigest = MessageDigest.getInstance(HASH_TYPE)
            messageDigest.update(appInfo.toByteArray(StandardCharsets.UTF_8))
            val hashSignature = messageDigest.digest().copyOfRange(0, NUM_HASHED_BYTES)
            var base64Hash = Base64.encodeToString(hashSignature, Base64.NO_PADDING or Base64.NO_WRAP)
            base64Hash = base64Hash.substring(0, NUM_BASE64_CHAR)
            base64Hash
        } catch (e: NoSuchAlgorithmException) {
            null
        }
    }
}
