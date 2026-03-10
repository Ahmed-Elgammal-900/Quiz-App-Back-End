import * as React from 'react';
import {
  Body,
  Button,
  Container,
  Head,
  Heading,
  Html,
  Preview,
  Section,
  Text,
  Hr,
  Font,
  Link,
} from '@react-email/components';

// interface PasswordResetEmailProps {
//   resetUrl: string;
//   userName?: string;
// }

// export const PasswordResetEmail = ({
//   resetUrl,
//   userName = 'there',
// }: PasswordResetEmailProps) => (
//   <Html>
//     <Head />
//     <Preview>Reset your password</Preview>
//     <Body style={main}>
//       <Container style={container}>
//         <Heading style={h1}>Reset Your Password</Heading>
//         <Text style={text}>Hi {userName},</Text>
//         <Text style={text}>
//           We received a request to reset your password. Click the button below
//           to create a new password:
//         </Text>
//         <Section style={buttonContainer}>
//           <Button style={button} href={resetUrl}>
//             Reset Password
//           </Button>
//         </Section>
//         <Text style={text}>
//           This link will expire in 5 minutes for security reasons.
//         </Text>
//         <Hr style={hr} />
//         <Text style={footer}>
//           If you didn't request this, please ignore this email or contact
//           support if you have concerns.
//         </Text>
//       </Container>
//     </Body>
//   </Html>
// );

// const main = {
//   backgroundColor: '#f6f9fc',
//   fontFamily:
//     '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Ubuntu,sans-serif',
// };

// const container = {
//   backgroundColor: '#ffffff',
//   margin: '0 auto',
//   padding: '20px 0 48px',
//   marginBottom: '64px',
// };

// const h1 = {
//   color: '#333',
//   fontSize: '24px',
//   fontWeight: 'bold',
//   margin: '40px 0',
//   padding: '0',
//   textAlign: 'center' as const,
// };

// const text = {
//   color: '#333',
//   fontSize: '16px',
//   lineHeight: '26px',
//   margin: '16px 20px',
// };

// const buttonContainer = {
//   textAlign: 'center' as const,
//   margin: '32px 0',
// };

// const button = {
//   backgroundColor: '#4CAF50',
//   borderRadius: '5px',
//   color: '#fff',
//   fontSize: '16px',
//   fontWeight: 'bold',
//   textDecoration: 'none',
//   textAlign: 'center' as const,
//   display: 'block',
//   padding: '12px 24px',
// };

// const hr = {
//   borderColor: '#e6ebf1',
//   margin: '20px 0',
// };

// const footer = {
//   color: '#8898aa',
//   fontSize: '12px',
//   lineHeight: '16px',
//   margin: '16px 20px',
// };

// export default PasswordResetEmail;

// ─────────────────────────────────────────────────────────────
//  Props
// ─────────────────────────────────────────────────────────────
interface ResetPasswordEmailProps {
  /** Full reset URL (required) */
  resetUrl: string;
  /** Your application / brand name */
  appName?: string;
  /** Minutes until the reset link expires */
  expiryMins?: number;
  /** Optional recipient name for personalised greeting */
  recipientName?: string;
  /** Support / reply-to email address */
  supportEmail?: string;
  /** Physical company address shown in footer */
  companyAddress?: string;
  /** Hex color used for the accent stripe and CTA button */
  primaryColor?: string;
}

// ─────────────────────────────────────────────────────────────
//  Template
// ─────────────────────────────────────────────────────────────
export const ResetPasswordEmail = ({
  resetUrl = 'https://yourapp.com/reset-password?token=abc123',
  appName = 'YourApp',
  expiryMins = 30,
  recipientName = '',
  supportEmail = 'support@yourapp.com',
  companyAddress = '123 Main St, San Francisco CA 94105',
  primaryColor = '#1a1a1a',
}: ResetPasswordEmailProps) => {
  const previewText = `Reset your ${appName} password`;

  return (
    <Html lang="en" dir="ltr">
      <Head>
        <Font
          fontFamily="Georgia"
          fallbackFontFamily="Times New Roman"
          webFont={undefined}
          fontWeight={400}
          fontStyle="normal"
        />
        <title>{previewText}</title>
      </Head>

      <Preview>{previewText}</Preview>

      <Body style={styles.body}>
        <Container style={styles.container}>
          {/* ── Top accent stripe ── */}
          <Section
            style={{ ...styles.accentStripe, backgroundColor: primaryColor }}
          />

          {/* ── Main content ── */}
          <Section style={styles.content}>
            {/* Brand mark */}
            <Section style={styles.brandRow}>
              <span
                style={{ ...styles.logoMark, backgroundColor: primaryColor }}
              >
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 14 14"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <circle
                    cx="7"
                    cy="7"
                    r="5.5"
                    stroke="#faf9f6"
                    strokeWidth="2.5"
                  />
                </svg>
              </span>
              <Text style={{ ...styles.brandName, color: primaryColor }}>
                {appName}
              </Text>
            </Section>

            {/* Lock icon */}
            <Section style={styles.iconSection}>
              <span
                style={{
                  ...styles.iconWrap,
                  backgroundColor: `${primaryColor}12`,
                  border: `1.5px solid ${primaryColor}22`,
                }}
              >
                <svg
                  width="28"
                  height="28"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <rect
                    x="3"
                    y="11"
                    width="18"
                    height="11"
                    rx="2"
                    stroke={primaryColor}
                    strokeWidth="1.8"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M7 11V7a5 5 0 0 1 10 0v4"
                    stroke={primaryColor}
                    strokeWidth="1.8"
                    strokeLinecap="round"
                  />
                  <circle cx="12" cy="16" r="1.5" fill={primaryColor} />
                </svg>
              </span>
            </Section>

            {/* Heading */}
            <Heading as="h1" style={styles.heading}>
              Reset your password
            </Heading>

            {/* Body copy */}
            <Text style={styles.bodyText}>
              {recipientName ? `Hi ${recipientName}, we` : 'We'} received a
              request to reset the password for your{' '}
              <strong style={{ color: '#1a1a1a' }}>{appName}</strong> account.
              Click the button below to choose a new password.
            </Text>

            <Text style={styles.expiryText}>
              ⏱ This link expires in {expiryMins} minute
              {expiryMins !== 1 ? 's' : ''}
            </Text>

            {/* ── CTA Button ── */}
            <Section style={styles.buttonSection}>
              <Button
                href={resetUrl}
                style={{ ...styles.button, backgroundColor: primaryColor }}
              >
                Reset Password →
              </Button>
            </Section>

            {/* Fallback URL */}
            <Text style={styles.fallbackLabel}>
              Or copy and paste this link into your browser:
            </Text>
            <Section style={styles.urlBox}>
              <Text style={styles.urlText}>
                <Link
                  href={resetUrl}
                  style={{ ...styles.urlLink, color: primaryColor }}
                >
                  {resetUrl}
                </Link>
              </Text>
            </Section>

            {/* Security notice */}
            <Section style={styles.noticeSection}>
              <Text style={styles.noticeText}>
                If you didn&apos;t request a password reset, please ignore this
                email or{' '}
                <Link
                  href={`mailto:${supportEmail}`}
                  style={{ color: '#999', textDecoration: 'underline' }}
                >
                  contact support
                </Link>{' '}
                immediately. Your password will remain unchanged.
              </Text>
            </Section>

            <Hr style={styles.divider} />

            {/* Footer */}
            <Text style={styles.footerText}>
              Need help?{' '}
              <Link href={`mailto:${supportEmail}`} style={styles.footerLink}>
                {supportEmail}
              </Link>
            </Text>
            <Text style={styles.footerText}>
              {appName} &middot; {companyAddress}
            </Text>
          </Section>

          {/* ── Footer link bar ── */}
          <Section style={styles.linkBar}>
            <Link href="#" style={styles.linkBarItem}>
              Unsubscribe
            </Link>
            <Text style={styles.linkBarSep}>&nbsp;&middot;&nbsp;</Text>
            <Link href="#" style={styles.linkBarItem}>
              Privacy Policy
            </Link>
            <Text style={styles.linkBarSep}>&nbsp;&middot;&nbsp;</Text>
            <Link href="#" style={styles.linkBarItem}>
              Terms
            </Link>
          </Section>
        </Container>
      </Body>
    </Html>
  );
};

// ─────────────────────────────────────────────────────────────
//  Preview defaults (react-email dev server)
// ─────────────────────────────────────────────────────────────
ResetPasswordEmail.PreviewProps = {
  resetUrl: 'https://yourapp.com/reset-password?token=abc123xyz',
  appName: 'YourApp',
  expiryMins: 30,
  recipientName: 'John',
  supportEmail: 'support@yourapp.com',
  companyAddress: '123 Main St, San Francisco CA 94105',
  primaryColor: '#1a1a1a',
} satisfies ResetPasswordEmailProps;

export default ResetPasswordEmail;

// ─────────────────────────────────────────────────────────────
//  Styles  (all inline — required for email client compat.)
// ─────────────────────────────────────────────────────────────
const styles: Record<string, React.CSSProperties> = {
  body: {
    backgroundColor: '#f0ede6',
    fontFamily: "Georgia, 'Times New Roman', Times, serif",
    margin: '0',
    padding: '40px 0',
  },
  container: {
    backgroundColor: '#faf9f6',
    borderRadius: '6px',
    maxWidth: '560px',
    margin: '0 auto',
    overflow: 'hidden',
  },

  accentStripe: {
    height: '4px',
    width: '100%',
  },

  content: {
    padding: '48px 52px 40px',
  },

  // Brand
  brandRow: {
    marginBottom: '36px',
  },
  logoMark: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '30px',
    height: '30px',
    borderRadius: '6px',
    verticalAlign: 'middle',
    marginRight: '10px',
    padding: '8px',
  },
  brandName: {
    display: 'inline',
    fontSize: '15px',
    fontWeight: '700',
    letterSpacing: '0.3px',
    margin: '0',
    verticalAlign: 'middle',
  },

  // Lock icon
  iconSection: {
    marginBottom: '28px',
  },
  iconWrap: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '60px',
    height: '60px',
    borderRadius: '14px',
    padding: '16px',
  },

  // Typography
  heading: {
    fontSize: '26px',
    fontWeight: '700',
    color: '#1a1a1a',
    lineHeight: '1.25',
    letterSpacing: '-0.4px',
    margin: '0 0 16px',
  },
  bodyText: {
    fontSize: '15px',
    color: '#666666',
    lineHeight: '1.75',
    margin: '0 0 8px',
  },
  expiryText: {
    fontSize: '13px',
    color: '#aaaaaa',
    lineHeight: '1.6',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.3px',
    margin: '0 0 32px',
  },

  // CTA Button
  buttonSection: {
    marginBottom: '28px',
    textAlign: 'left' as const,
  },
  button: {
    color: '#ffffff',
    fontSize: '14px',
    fontWeight: '600',
    fontFamily: "Georgia, 'Times New Roman', Times, serif",
    letterSpacing: '0.4px',
    padding: '14px 32px',
    borderRadius: '5px',
    textDecoration: 'none',
    display: 'inline-block',
  },

  // Fallback URL
  fallbackLabel: {
    fontSize: '12px',
    color: '#aaaaaa',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.3px',
    margin: '0 0 10px',
  },
  urlBox: {
    backgroundColor: '#f0ede6',
    borderRadius: '4px',
    padding: '12px 16px',
    marginBottom: '32px',
    border: '1px solid #e8e4dc',
  },
  urlText: {
    margin: '0',
    fontSize: '12px',
    wordBreak: 'break-all' as const,
    fontFamily: "'Courier New', Courier, monospace",
  },
  urlLink: {
    textDecoration: 'underline',
    wordBreak: 'break-all' as const,
  },

  // Security notice
  noticeSection: {
    borderLeft: '3px solid #e0ddd6',
    paddingLeft: '16px',
    marginBottom: '36px',
  },
  noticeText: {
    fontSize: '13px',
    color: '#999999',
    lineHeight: '1.7',
    margin: '0',
  },

  divider: {
    borderColor: '#e8e4dc',
    margin: '0 0 24px',
  },

  footerText: {
    fontSize: '12px',
    color: '#bbbbbb',
    lineHeight: '1.7',
    fontFamily: "'Courier New', Courier, monospace",
    margin: '0 0 4px',
  },
  footerLink: {
    color: '#999999',
    textDecoration: 'underline',
  },

  linkBar: {
    backgroundColor: '#f0ede6',
    borderTop: '1px solid #e8e4dc',
    padding: '14px 52px',
    textAlign: 'center' as const,
  },
  linkBarItem: {
    fontSize: '11px',
    color: '#bbbbbb',
    textDecoration: 'underline',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.5px',
    margin: '0 6px',
  },
  linkBarSep: {
    display: 'inline',
    fontSize: '11px',
    color: '#cccccc',
    margin: '0',
  },
};
