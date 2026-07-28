import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Modal,
  ActivityIndicator,
  ScrollView,} from 'react-native';
import { openExternal } from '../utils/openExternal';
import { Ionicons } from '@expo/vector-icons';
import { useTheme } from '../contexts/ThemeContext';
import { getTeeAttestation, type OpenRouterModel, type TeeAttestation } from '../services/modelService';

// Public docs explaining how to independently verify an attestation report,
// per confidential-compute provider (routed by model-id prefix).
const NEAR_VERIFY_DOCS = 'https://docs.near.ai/cloud/private-inference/';
const TINFOIL_VERIFY_DOCS = 'https://docs.tinfoil.sh/verification/verification-in-tinfoil';

interface Props {
  visible: boolean;
  model: OpenRouterModel | null;
  onClose: () => void;
}

/**
 * Explains confidential compute in plain language and, on demand, fetches &
 * displays the live signed TEE attestation report — NEAR (Intel TDX quote +
 * NVIDIA GPU evidence + signature) or Tinfoil (AMD SEV-SNP guest report),
 * routed by the model-id prefix. Evidence rows render only when that evidence
 * type applies to the provider's stack. v1 surfaces the report for
 * inspection; full on-device cryptographic verification is a follow-up.
 */
const AttestationSheet: React.FC<Props> = ({ visible, model, onClose }) => {
  const { theme, ambientSurface, ambientAccent, ambientOnAccent } = useTheme();
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attestation, setAttestation] = useState<TeeAttestation | null>(null);

  // Reset transient state whenever the sheet is opened for a (new) model.
  useEffect(() => {
    if (!visible) return;
    setLoading(false);
    setError(null);
    setAttestation(null);
  }, [visible, model?.id]);

  const fetchReport = async () => {
    if (!model) return;
    setLoading(true);
    setError(null);
    try {
      const result = await getTeeAttestation(model.id);
      setAttestation(result);
    } catch (e: any) {
      setError(e?.message || t('attestation.error'));
    } finally {
      setLoading(false);
    }
  };

  const Check: React.FC<{ ok: boolean; label: string }> = ({ ok, label }) => (
    <View style={s.checkRow}>
      <Ionicons
        name={ok ? 'checkmark-circle' : 'close-circle'}
        size={18}
        color={ok ? '#10B981' : theme.tertiaryText}
      />
      <Text style={[s.checkLabel, { color: theme.text }]}>{label}</Text>
    </View>
  );

  const s = styles(theme, ambientSurface);

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <TouchableOpacity style={s.backdrop} activeOpacity={1} onPress={onClose}>
        <TouchableOpacity activeOpacity={1} style={s.card}>
          <View style={s.header}>
            <View style={s.titleRow}>
              <Ionicons name="lock-closed" size={18} color="#A855F7" />
              <Text style={[s.title, { color: theme.text }]}>{t('attestation.title')}</Text>
            </View>
            <TouchableOpacity onPress={onClose} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
              <Ionicons name="close" size={22} color={theme.secondaryText} />
            </TouchableOpacity>
          </View>

          <ScrollView style={{ maxHeight: 460 }} contentContainerStyle={{ paddingBottom: 8 }}>
            {!!model && (
              <Text style={[s.modelName, { color: theme.secondaryText }]} numberOfLines={1}>
                {model.name}
              </Text>
            )}

            <Text style={[s.body, { color: theme.secondaryText }]}>
              {t('attestation.intro', {
                stack: model?.teeStack || 'Intel TDX + NVIDIA confidential GPU',
              })}
            </Text>

            {/* Benefit bullets */}
            <View style={s.bullets}>
              <Check ok label={t('attestation.benefit1')} />
              <Check ok label={t('attestation.benefit2')} />
              <Check ok label={t('attestation.benefit3')} />
            </View>

            {attestation && (
              <View style={[s.reportBox, { backgroundColor: theme.tertiaryBackground, borderColor: theme.border }]}>
                <Text style={[s.reportTitle, { color: theme.text }]}>{t('attestation.reportTitle')}</Text>
                {typeof attestation.hasTdxQuote === 'boolean' && (
                  <Check ok={attestation.hasTdxQuote} label={t('attestation.tdxQuote')} />
                )}
                {typeof attestation.hasGpuEvidence === 'boolean' && (
                  <Check ok={attestation.hasGpuEvidence} label={t('attestation.gpuEvidence')} />
                )}
                {typeof attestation.hasSevSnp === 'boolean' && (
                  <Check ok={attestation.hasSevSnp} label={t('attestation.sevSnp')} />
                )}
                <Check ok={attestation.hasSignature} label={t('attestation.signature')} />
                {!!attestation.nonce && (
                  <Text style={[s.meta, { color: theme.tertiaryText }]} numberOfLines={1}>
                    {t('attestation.nonce')}: {attestation.nonce}
                  </Text>
                )}
                <Text style={[s.meta, { color: theme.tertiaryText }]} numberOfLines={1}>
                  {t('attestation.verifiedAt')}: {new Date(attestation.verifiedAt).toLocaleString()}
                </Text>
              </View>
            )}

            {!!error && <Text style={[s.error, { color: '#EF4444' }]}>{error}</Text>}
          </ScrollView>

          {!attestation && (
            <TouchableOpacity
              style={[s.primaryBtn, { backgroundColor: ambientAccent, opacity: loading ? 0.6 : 1 }]}
              onPress={fetchReport}
              disabled={loading}
            >
              {loading ? (
                <ActivityIndicator color={ambientOnAccent} size="small" />
              ) : (
                <Text style={[s.primaryBtnText, { color: ambientOnAccent }]}>{t('attestation.viewReport')}</Text>
              )}
            </TouchableOpacity>
          )}

          <TouchableOpacity
            onPress={() =>
              openExternal(model?.id.startsWith('tinfoil/') ? TINFOIL_VERIFY_DOCS : NEAR_VERIFY_DOCS)
            }
          >
            <Text style={[s.link, { color: ambientAccent }]}>{t('attestation.learnMore')}</Text>
          </TouchableOpacity>
        </TouchableOpacity>
      </TouchableOpacity>
    </Modal>
  );
};

const styles = (theme: any, ambientSurface: string) =>
  StyleSheet.create({
    backdrop: {
      flex: 1,
      backgroundColor: theme.overlay,
      justifyContent: 'center',
      alignItems: 'center',
      padding: 20,
    },
    card: {
      width: '100%',
      maxWidth: 460,
      borderRadius: 16,
      padding: 18,
      // Ambient-tinted surface so the dialog sits in the chosen wash rather than
      // reading as a flat neutral box over it. (`off` = the neutral theme value.)
      backgroundColor: ambientSurface,
      borderWidth: StyleSheet.hairlineWidth,
      borderColor: theme.border,
    },
    header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 },
    titleRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    title: { fontSize: 17, fontWeight: '700' },
    modelName: { fontSize: 13, fontWeight: '600', marginBottom: 10 },
    body: { fontSize: 14, lineHeight: 20, marginBottom: 14 },
    bullets: { gap: 8, marginBottom: 6 },
    checkRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
    checkLabel: { fontSize: 13, flex: 1 },
    reportBox: { marginTop: 14, padding: 12, borderRadius: 10, borderWidth: StyleSheet.hairlineWidth, gap: 8 },
    reportTitle: { fontSize: 13, fontWeight: '700', marginBottom: 2 },
    meta: { fontSize: 11, fontFamily: 'monospace' },
    error: { fontSize: 13, marginTop: 12 },
    primaryBtn: { marginTop: 16, borderRadius: 12, paddingVertical: 13, alignItems: 'center', justifyContent: 'center' },
    primaryBtnText: { fontSize: 15, fontWeight: '700' },
    link: { fontSize: 13, fontWeight: '600', textAlign: 'center', marginTop: 14 },
  });

export default AttestationSheet;
