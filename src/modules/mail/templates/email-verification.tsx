import * as React from 'react';
import {
  Body,
  Container,
  Font,
  Head,
  Heading,
  Hr,
  Html,
  Link,
  Preview,
  Row,
  Section,
  Text,
} from '@react-email/components';

// ─────────────────────────────────────────────────────────────
//  Props
// ─────────────────────────────────────────────────────────────
interface OTPEmailTemplateProps {
  /** The 6-digit OTP code (required) */
  otp: string;
  /** Your application / brand name */
  appName?: string;
  /** Minutes until the OTP expires */
  expiryMins?: number;
  /** Optional recipient name or email for personalised greeting */
  recipientName?: string;
  /** Support / reply-to email address */
  supportEmail?: string;
  /** Physical company address shown in footer */
  companyAddress?: string;
  /** Hex color used for the accent stripe and OTP block */
  primaryColor?: string;
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────
/** Splits "847291" → "847 291" for readability */
const formatOtp = (otp: string) => otp.replace(/^(\d{3})(\d{3})$/, '$1 $2');

// ─────────────────────────────────────────────────────────────
//  Template
// ─────────────────────────────────────────────────────────────
export const OTPEmailTemplate = ({
  otp = '000000',
  appName = 'YourApp',
  expiryMins = 10,
  recipientName = '',
  supportEmail = 'support@yourapp.com',
  companyAddress = '123 Main St, San Francisco CA 94105',
  primaryColor = '#1a1a1a',
}: OTPEmailTemplateProps) => {
  const previewText = `Your ${appName} verification code is ${otp}`;

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
            <Row>
              <Section style={styles.brandRow}>
                <span
                  style={{ ...styles.logoMark, backgroundColor: primaryColor }}
                >
                  {/* Inline SVG circle — works in all email clients */}
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
            </Row>

            {/* Heading */}
            <Heading as="h1" style={styles.heading}>
              Verify your email address
            </Heading>

            {/* Greeting + instruction */}
            <Text style={styles.bodyText}>
              {recipientName ? `Hi ${recipientName}, use` : 'Use'} the one-time
              code below to complete your sign-in to{' '}
              <strong style={{ color: '#1a1a1a' }}>{appName}</strong>.
            </Text>

            {/* Expiry note */}
            <Text style={styles.expiryText}>
              ⏱ Expires in {expiryMins} minute{expiryMins !== 1 ? 's' : ''}
            </Text>

            {/* ── OTP block ── */}
            <Section
              style={{ ...styles.otpSection, backgroundColor: primaryColor }}
            >
              <Text style={styles.otpLabel}>One-Time Passcode</Text>
              <Text style={styles.otpCode}>{formatOtp(otp)}</Text>
              <Text style={styles.otpHint}>
                Enter this code to verify your identity.
              </Text>
            </Section>

            {/* Security notice */}
            <Section style={styles.noticeSection}>
              <Text style={styles.noticeText}>
                If you didn&apos;t request this code, you can safely ignore this
                email — your account is safe. Never share this code with anyone.{' '}
                <strong style={{ color: '#bbb' }}>{appName}</strong> will never
                ask you for your OTP.
              </Text>
            </Section>

            <Hr style={styles.divider} />

            {/* Footer */}
            <Text style={styles.footerText}>
              Questions? Email us at{' '}
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
            <Text style={styles.linkBarSep}>&middot;</Text>
            <Link href="#" style={styles.linkBarItem}>
              Privacy Policy
            </Link>
            <Text style={styles.linkBarSep}>&middot;</Text>
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
//  Default export with preview defaults
// ─────────────────────────────────────────────────────────────
OTPEmailTemplate.PreviewProps = {
  otp: '847291',
  appName: 'YourApp',
  expiryMins: 10,
  recipientName: 'John',
  supportEmail: 'support@yourapp.com',
  companyAddress: '123 Main St, San Francisco CA 94105',
  primaryColor: '#1a1a1a',
} satisfies OTPEmailTemplateProps;

export default OTPEmailTemplate;

// ─────────────────────────────────────────────────────────────
//  Styles  (inline — required for email client compatibility)
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

  // Accent stripe
  accentStripe: {
    height: '4px',
    width: '100%',
  },

  // Main body padding
  content: {
    padding: '48px 52px 40px',
  },

  // Brand row
  brandRow: {
    display: 'flex',
    alignItems: 'center',
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

  // Typography
  heading: {
    fontSize: '26px',
    fontWeight: '700',
    color: '#1a1a1a',
    lineHeight: '1.25',
    letterSpacing: '-0.4px',
    margin: '0 0 14px',
  },
  bodyText: {
    fontSize: '15px',
    color: '#666666',
    lineHeight: '1.7',
    margin: '0 0 6px',
  },
  expiryText: {
    fontSize: '13px',
    color: '#aaaaaa',
    lineHeight: '1.6',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.3px',
    margin: '0 0 32px',
  },

  // OTP block
  otpSection: {
    borderRadius: '8px',
    padding: '32px 28px 24px',
    marginBottom: '32px',
    textAlign: 'center',
  },
  otpLabel: {
    fontSize: '10px',
    color: 'rgba(255,255,255,0.45)',
    letterSpacing: '3px',
    textTransform: 'uppercase',
    fontFamily: "'Courier New', Courier, monospace",
    margin: '0 0 16px',
  },
  otpCode: {
    fontSize: '48px',
    fontWeight: '800',
    color: '#ffffff',
    letterSpacing: '14px',
    lineHeight: '1',
    margin: '0 0 16px',
  },
  otpHint: {
    fontSize: '11px',
    color: 'rgba(255,255,255,0.35)',
    letterSpacing: '0.5px',
    fontFamily: "'Courier New', Courier, monospace",
    margin: '0',
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

  // Divider
  divider: {
    borderColor: '#e8e4dc',
    margin: '0 0 24px',
  },

  // Footer
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

  // Link bar
  linkBar: {
    backgroundColor: '#f0ede6',
    borderTop: '1px solid #e8e4dc',
    padding: '14px 52px',
    textAlign: 'center',
  },
  linkBarItem: {
    fontSize: '11px',
    color: '#bbbbbb',
    textDecoration: 'underline',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.5px',
    margin: '0 8px',
  },
  linkBarSep: {
    display: 'inline',
    fontSize: '11px',
    color: '#cccccc',
    margin: '0',
  },
};
