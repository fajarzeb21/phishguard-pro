import { useState } from "react";
import {
LockKeyhole,
Eye,
EyeOff,
ShieldCheck,
ShieldAlert,
CheckCircle,
XCircle,
RefreshCw,
} from "lucide-react";

function PasswordChecker() {
const [password, setPassword] = useState("");
const [showPassword, setShowPassword] = useState(false);

const checks = [
{
label: "At least 8 characters",
passed: password.length >= 8,
},
{
label: "At least 12 characters (recommended)",
passed: password.length >= 12,
},
{
label: "Contains uppercase letters (A–Z)",
passed: /[A-Z]/.test(password),
},
{
label: "Contains lowercase letters (a–z)",
passed: /[a-z]/.test(password),
},
{
label: "Contains numbers (0–9)",
passed: /[0-9]/.test(password),
},
{
label: "Contains special characters",
passed: /[^A-Za-z0-9]/.test(password),
},
];

const passedChecks = checks.filter((check) => check.passed).length;

let strength = "Enter a password";
let strengthClass = "unknown";
let score = 0;

if (password.length > 0) {
score = Math.round((passedChecks / checks.length) * 100);


if (password.length < 8) {
  strength = "Very Weak";
  strengthClass = "very-weak";
} else if (passedChecks <= 3) {
  strength = "Weak";
  strengthClass = "weak";
} else if (passedChecks === 4) {
  strength = "Medium";
  strengthClass = "medium";
} else if (passedChecks === 5) {
  strength = "Strong";
  strengthClass = "strong";
} else {
  strength = "Very Strong";
  strengthClass = "very-strong";
}


}

function resetChecker() {
setPassword("");
setShowPassword(false);
}

return ( <div className="page-content password-checker-page"> <div className="page-heading"> <div> <span className="eyebrow">PASSWORD SECURITY</span> <h1>Password Strength Checker</h1> <p>
Evaluate password complexity and learn how to improve it. </p> </div> </div>


  <section className="panel password-checker-panel">
    <div className="password-checker-intro">
      <div className="form-intro-icon">
        <LockKeyhole size={25} />
      </div>

      <h3>Check Your Password</h3>

      <p>
        Enter a password to evaluate its length and character variety.
        Your password is checked locally in this browser.
      </p>
    </div>

    <div className="password-input-group">
      <label htmlFor="password-checker-input">
        Password
      </label>

      <div className="password-input-wrapper">
        <LockKeyhole size={19} />

        <input
          id="password-checker-input"
          type={showPassword ? "text" : "password"}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          placeholder="Enter a password to check"
          autoComplete="new-password"
          spellCheck="false"
        />

        <button
          type="button"
          className="icon-button"
          onClick={() => setShowPassword(!showPassword)}
          aria-label={showPassword ? "Hide password" : "Show password"}
        >
          {showPassword ? (
            <EyeOff size={19} />
          ) : (
            <Eye size={19} />
          )}
        </button>
      </div>

      <p className="form-hint">
        For privacy, use a sample password rather than a password you
        currently use for an important account.
      </p>
    </div>

    {password.length > 0 && (
      <>
        <div className={`password-strength-card strength-${strengthClass}`}>
          <div className="password-strength-heading">
            <div className="password-strength-icon">
              {strength === "Strong" || strength === "Very Strong" ? (
                <ShieldCheck size={23} />
              ) : (
                <ShieldAlert size={23} />
              )}
            </div>

            <div>
              <span>Estimated Password Strength</span>
              <h2>{strength}</h2>
            </div>

            <strong>{score}%</strong>
          </div>

          <div
            className="password-strength-track"
            role="progressbar"
            aria-label="Password complexity checks passed"
            aria-valuenow={score}
            aria-valuemin={0}
            aria-valuemax={100}
          >
            <div
              className="password-strength-fill"
              style={{ width: `${score}%` }}
            />
          </div>

          <p>
            This estimate measures basic complexity rules. It does not
            guarantee that a password is difficult to guess or has never
            been exposed in a data breach.
          </p>
        </div>

        <div className="password-checklist">
          <div className="section-heading">
            <div>
              <h3>Security Checklist</h3>
              <p>Review the password characteristics below.</p>
            </div>

            <span className="findings-count">
              {passedChecks}/{checks.length} checks
            </span>
          </div>

          <div className="password-checklist-items">
            {checks.map((check) => (
              <div
                className="password-check-item"
                key={check.label}
              >
                {check.passed ? (
                  <CheckCircle size={19} />
                ) : (
                  <XCircle size={19} />
                )}

                <span>{check.label}</span>

                <strong>
                  {check.passed ? "Passed" : "Not met"}
                </strong>
              </div>
            ))}
          </div>
        </div>

        <div className="password-recommendations">
          <h3>Recommendations</h3>

          <ul>
            {password.length < 12 && (
              <li>
                Use at least 12 characters, preferably a longer,
                randomly generated password.
              </li>
            )}

            {!/[A-Z]/.test(password) && (
              <li>
                Consider including uppercase letters.
              </li>
            )}

            {!/[a-z]/.test(password) && (
              <li>
                Include lowercase letters if appropriate.
              </li>
            )}

            {!/[0-9]/.test(password) && (
              <li>
                Consider including numbers.
              </li>
            )}

            {!/[^A-Za-z0-9]/.test(password) && (
              <li>
                Consider including special characters.
              </li>
            )}

            {passedChecks === checks.length && (
              <li>
                All basic complexity checks passed. Prefer a unique
                password generated by a trusted password manager.
              </li>
            )}

            <li>
              Avoid personal information, predictable patterns, and
              passwords reused across different accounts.
            </li>
          </ul>
        </div>

        <button
          type="button"
          className="secondary-button password-reset-button"
          onClick={resetChecker}
        >
          <RefreshCw size={16} />
          Check Another Password
        </button>
      </>
    )}

    {!password && (
      <div className="password-empty-state">
        <ShieldCheck size={30} />
        <h3>Ready to Check</h3>
        <p>
          Enter a sample password above to see its complexity checks
          and recommendations.
        </p>
      </div>
    )}
  </section>

  <div className="disclaimer-box">
    <ShieldCheck size={20} />

    <div>
      <strong>Privacy Notice</strong>
      <p>
        This checker evaluates the password in your browser. It does
        not make an API request or save the password to investigation
        history. Its strength rating is a basic estimate, not a
        guarantee of security.
      </p>
    </div>
  </div>
</div>


);
}

export default PasswordChecker;
