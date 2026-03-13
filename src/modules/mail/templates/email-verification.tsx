import * as React from 'react';
import {
  Body,
  Column,
  Container,
  Font,
  Head,
  Heading,
  Html,
  Preview,
  Row,
  Section,
  Text,
} from '@react-email/components';

interface OTPEmailTemplateProps {
  otp: string;
  appName?: string;
  expiryMins?: number;
  recipientName?: string;
  primaryColor?: string;
}

/**
 * Formats a 6-digit OTP into "111 111" display format
 * Returns original string unchanged if input is not exactly 6 digits
 * @param otp OTP string
 * @returns parsed OTP
 */
const formatOtp = (otp: string) => otp.replace(/^(\d{3})(\d{3})$/, '$1 $2');

export const OTPEmailTemplate = ({
  otp,
  appName = 'Quizzer',
  expiryMins = 10,
  recipientName = '',
  primaryColor = '#0f1fd1',
}: OTPEmailTemplateProps) => {
  const previewText = `Your ${appName} verification code is ${otp}`;
  const initial = appName.charAt(0).toUpperCase();

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
            {/* ── Brand mark ── */}
            <Row style={styles.brandRow}>
              {/* Logo column — fixed width */}
              <Column style={styles.logoColumn}>
                <div
                  style={{ ...styles.logoMark, backgroundColor: primaryColor }}
                >
                  <span style={styles.logoInitial}>{initial}</span>
                </div>
              </Column>

              {/* App name column */}
              <Column style={styles.brandNameColumn}>
                <Text style={{ ...styles.brandName, color: primaryColor }}>
                  {appName}
                </Text>
              </Column>
            </Row>

            {/* Heading */}
            <Heading as="h1" style={styles.heading}>
              Verify your email address
            </Heading>

            {/* Greeting + instruction */}
            <Text style={styles.bodyText}>
              {recipientName ? `Hi ${recipientName}, use` : 'Use'} the one-time
              code below to verify your email address for{' '}
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
                <strong style={{ color: 'black' }}>{appName}</strong> will never
                ask you for your OTP.
              </Text>
            </Section>
          </Section>
        </Container>
      </Body>
    </Html>
  );
};

export default OTPEmailTemplate;

const styles: Record<string, React.CSSProperties> = {
  body: {
    backgroundColor: '#eee',
    fontFamily: "Georgia, 'Times New Roman', Times, serif",
    margin: '0',
    padding: '40px 0',
  },
  container: {
    backgroundColor: 'white',
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
    paddingTop: '48px',
    paddingBottom: '40px',
    paddingLeft: '52px',
    paddingRight: '52px',
  },

  brandRow: {
    marginBottom: '36px',
  },
  logoColumn: {
    width: '44px',
    verticalAlign: 'middle',
  },
  logoMark: {
    width: '36px',
    height: '36px',
    borderRadius: '8px',
    textAlign: 'center',
    verticalAlign: 'middle',
    display: 'table',
  },
  logoInitial: {
    display: 'table-cell',
    verticalAlign: 'middle',
    textAlign: 'center',
    color: '#ffffff',
    fontSize: '18px',
    fontWeight: '800',
    fontFamily: "Georgia, 'Times New Roman', Times, serif",
    letterSpacing: '-0.5px',
    lineHeight: '1',
  },
  brandNameColumn: {
    verticalAlign: 'middle',
  },
  brandName: {
    display: 'inline',
    fontSize: '15px',
    fontWeight: '700',
    letterSpacing: '0.3px',
    marginTop: '0',
    marginBottom: '0',
    marginLeft: '0',
    marginRight: '0',
  },

  heading: {
    fontSize: '26px',
    fontWeight: '700',
    color: '#1a1a1a',
    lineHeight: '1.25',
    letterSpacing: '-0.4px',
    marginTop: '0',
    marginBottom: '14px',
    marginLeft: '0',
    marginRight: '0',
  },
  bodyText: {
    fontSize: '15px',
    color: '#666666',
    lineHeight: '1.7',
    marginTop: '0',
    marginBottom: '6px',
    marginLeft: '0',
    marginRight: '0',
  },
  expiryText: {
    fontSize: '13px',
    color: '#aaaaaa',
    lineHeight: '1.6',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.3px',
    marginTop: '0',
    marginBottom: '32px',
    marginLeft: '0',
    marginRight: '0',
  },

  otpSection: {
    borderRadius: '8px',
    paddingTop: '32px',
    paddingBottom: '24px',
    paddingLeft: '28px',
    paddingRight: '28px',
    marginBottom: '32px',
    textAlign: 'center',
  },
  otpLabel: {
    fontSize: '10px',
    color: 'rgba(255,255,255,0.45)',
    letterSpacing: '3px',
    textTransform: 'uppercase',
    fontFamily: "'Courier New', Courier, monospace",
    marginTop: '0',
    marginBottom: '16px',
    marginLeft: '0',
    marginRight: '0',
  },
  otpCode: {
    fontSize: '48px',
    fontWeight: '800',
    color: '#ffffff',
    letterSpacing: '14px',
    lineHeight: '1',
    marginTop: '0',
    marginBottom: '16px',
    marginLeft: '0',
    marginRight: '0',
  },
  otpHint: {
    fontSize: '11px',
    color: 'rgba(255,255,255,0.35)',
    letterSpacing: '0.5px',
    fontFamily: "'Courier New', Courier, monospace",
    margin: '0',
  },

  noticeSection: {
    borderLeft: '3px solid #d6d6d6',
    paddingLeft: '16px',
    marginBottom: '36px',
  },
  noticeText: {
    fontSize: '13px',
    color: '#999999',
    lineHeight: '1.7',
    margin: '0',
  },
};
