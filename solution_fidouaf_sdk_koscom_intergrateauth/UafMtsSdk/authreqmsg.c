#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include "Base64Encode.h"
#include "Base64Decode.h"
#include "UafMessageDefine.h"
#include "authreqmsg.h"

const char* S_SAUTHREQ = "{\"version\":\"1.0\",\"source\":8,\"target\":64,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"testuser\",\"sessionid\":\"9c5e121c7a764459a545c8ff903d2200\",\"errorcode\":\"00000000\",\"operation\":\"auth\",\"authrequestmsg\":\"W3siaGVhZGVyIjp7InVwdiI6eyJtYWpvciI6MSwibWlub3IiOjB9LCJvcCI6IkF1dGgiLCJhcHBJRCI6Imh0dHBzOi8vMjExLjIzNi4yNDYuNzc6OTAyNC9hcHBpZCIsInNlcnZlckRhdGEiOiI2M2RiMjk0MjI4ZDg0ZDQwYTMxMDU4MTZlMjM2NmEwYiIsImV4dHMiOlt7ImlkIjoic2ltcGxlcHVia2V5IiwiZGF0YSI6Ik1XVTVabU0wWXpNdFlqVmpZeTAwWlRBeExUbG1ORFF0TVRNelltRmpabVJrWWpZMiIsImZhaWxfaWZfdW5rbm93biI6ZmFsc2V9XX0sImNoYWxsZW5nZSI6ImQ4NWQ2YzhmOTgyYjQ1N2E4NjM4OGEzOGZlOWI1NDAyIiwicG9saWN5Ijp7ImFjY2VwdGVkIjpbW3siYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIlltTTJNemszWVdRdE1tVm1ZeTAwTUdVeUxUbGlabUV0WVRkak1HTTVOMlZtTkdRdyJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJZamN5TVRnNE16SXRaREUwT1MwMFkyWmxMV0l4TlRRdFlXVmlNbVE0WlRNNFlXVXciXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiWWpBek1tTmpNbU10TXpBM05pMDBNalEzTFRnNVlURXRZV05pTW1RNVlUbG1NR0ppIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIllqRXhaR1F4TWpBdFkyWXhaUzAwTnpOa0xUZ3lNR1V0WVRWa09EbGtZek0zT1RrMiJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJOVGd6WWpGaE1HTXRNREk0T1MwMFpUbGtMV0ZrTURFdE56azBZMkk1TlRoa1ltUmkiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiTTJNelpqWTNaRGd0TjJSallpMDBNbVl5TFRnek9UY3RaV1k0TTJSaE56RXpNVEkzIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIllqUXpaRE0wTUdZdE9ESXpOeTAwTWpRM0xXRTFZell0TVRRMlpEWXdNelJrWXpabSJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJNV0ptWVRFM1pEQXRabVU0TmkwMFpUbGtMV0U1WlRjdFpUZGlaVEEzWlRRMVkyTXoiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiT0Rka1pqbGxaRE10TURKalppMDBNVGt3TFdJeFpUa3RZamcwWmpNM1lqbG1OVGMyIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIk16UTVZelk1T0RVdE9XTXdZaTAwWXpZeUxUaGhaRGd0Wm1Zd00yRmlPR1UyWlRjeSJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJOVFk1WmpJeVpHUXRNMkZqWlMwME5ETTRMV0ZqWkdNdFpHUm1aV1E0TjJVd1pEVTQiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiWkRNeU9XUXlNRFl0WVRnd1pDMDBOak0zTFRrMk56TXRPVE0yTmpnNU1XTTVZakptIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIk1XTTFOekl3T0RJdE9HTXdPUzAwT1RnNExXRTNZekF0TXprME5qYzFPVFppTmpsayJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJZakF5TXpKbE1qUXROekF4WXkwME9HWXdMV0U0WkRFdE1tRTJOak0yTnpZM09XVTUiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiT1dVMVlqWTFZVEl0TlRabVpDMDBNbVkwTFdJMU5UVXRNVFppTjJNMk1UWXlaRGMzIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIllXRmxaREE0TXpRdE5URTNaUzAwTTJOa0xXSXdNbUl0WlRReVlXTTFaRE5tWlRZNSJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJaVGM1WldRMU4yWXRZV1ZtWVMwMFptVTRMVGd5TW1NdE9Ua3daalV6TnpVek9EZGsiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiWWpRMVpETXdZalV0T0RWaFlpMDBPR1psTFdFMlpXSXRaR1poTW1NeU1ETmxNREJtIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIlpUWTBaVGhsWW1JdE1qQm1PUzAwT1dSbExXSXlaREV0WmpZeU9XRTVNVEExWm1NMiJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJOamczTWpoaE5qSXROelF5TXkwME16WmtMVGxoWW1FdFpHUXpZMlJtWWpOa09XSTQiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiTkdZd1kyUTROVGN0TnpreE55MDBZemhsTFdFek9HTXRNalUzWlRReU9ESTVZelkxIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIk5tTTRZbVJpWW1FdFptWXlPQzAwT1RRM0xUbGtOV1l0T0RZMFpHVmhZakl4T1RWbCJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJNMk0yTkRRNE0yUXRaVE01WkMwMFlqVmxMVGszWWprdE1EQmpPR1F4WXpnM016azIiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWXpsbE5tSmhOV1F0WXpjd01pMDBaVEUyTFdJeVltSXRNekl4TURGalptVTRabVF6Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk5HUmpNR1l4TlRFdFl6RTRZaTAwWVRKakxUZ3paVFV0TUdWbE5UTmpNVGd3TW1GaiJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJaamRpT0dFNFpqY3RZVE5sWmkwME5qUXpMV0ZqTldFdFlXTmtZakU0WmpFMU1qVXciXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTjJNMk5tWXdOekF0T1RZNE9DMDBZamRtTFRrd05qSXROMkl5WVdNelpqRTVNVGt3Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIll6TmlOVGhrTWpNdE16Vm1ZaTAwWVRFNExUZzNZall0TlRnd05qQXlaR0U0TldKaiJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJNalUxT0RRM016SXROR0prTlMwMFkyWXdMV0kyTmpVdFpXRTROakJtWVRWaE56aGoiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTXprelpUbG1NV1F0TUdFeFpTMDBabVU0TFdFd05UUXROVFE1TlRJd056QmtOakl5Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk56TTJPVEkxWXpJdFlqRTVNaTAwWWpBNUxXSTROelF0WWpneU9UazFNalJqWmpKaiJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJPV0psWWpZeE1URXRObUZqWkMwME5UZzVMVGhrTVRZdFl6RTBOR0k0WWpBeE1qTTAiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWWpsaE5tRmpNell0WWpjMk1TMDBPV1JsTFRoaE1UQXRNams0TW1RMU9HWmtPVFkwIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk5tRm1OV0U0T1RNdE1ETTBPQzAwTm1ObExUZzRNekV0TXpFeU1qRmtNek00TURFMSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJPR1ZpTUdKalpHUXRZVGN5TkMwMFlXUTVMV0UyWVdJdE1HTXpZV000TWpaall6UXciXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWlRjd01qaG1NMlV0Tm1abE1TMDBNVGxsTFdJNU5UQXROV0UyT0RRMFpUZ3paVGxpIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk4yWTVZMlk1TkRRdE1tRmtZaTAwTnpnMkxUZzFOemN0WTJZNE1URTBaRGcwWXpKbSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJZemxrTWpObU1tSXROV1UzTUMwMFlXRTBMV0l3WldVdE9Ua3dNamMxWVdaak5XSmwiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWlRnMk5HRXhZamt0TnpFME15MDBOelZtTFdFMU16QXROVE5sWTJJNU9XRTRPR1E1Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIllqTTBORFkzWm1JdFpqUTFNeTAwTWpRMkxXRmpZVGN0TjJFd01qRmhPRFU1WTJVeCJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJZVGd6TldRM01HUXRaVGd3TnkwME5URXlMV0V3TkRRdFpqSmpaalJsT1RoaU5EZzMiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiT0RnMllXWTROak10T0dNM05DMDBaRGhoTFRnek5tTXRNamsyWW1Oak5XUTNNR013Il19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIk1EWTNNREkwWW1JdE5EQTBOeTAwT0RRNUxUZ3dPRFF0TlRVeE5EazJNV05tWVRGaSJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJaV05tTVRWbU5tVXRaRGN6TUMwME5tUmtMVGd3WlRBdE5tUmtOMkpqT0RZMFpqUTIiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiWTJaaE16YzVaREF0T0RKbU9DMDBNMkl6TFRrME5XWXROemN6TkdGbFlUTmhZV0kzIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIlpEZzFPREppWlRJdFkyVTFaQzAwT0RWa0xXSm1OekF0TnpnMVkyVXhOelUxTnpRdyJdfSx7ImFhaWQiOlsiQ0QwMSMwMDAxIl0sImtleUlEcyI6WyJNbVV4TUdJME4yRXROVFJoWlMwMFltWTNMV0UwTlRNdE56Z3pNall3WWpBNU9ETXoiXX0seyJhYWlkIjpbIkNEMDEjMDAwMSJdLCJrZXlJRHMiOlsiTnpabE5qSmlabVV0WldFMk1pMDBOakU0TFRnd00ySXRNMk5tWXpFd016UTJNMlZpIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIk9EWmxOR0ZpWldFdE5XTTNPUzAwTURJeUxXSmlabUV0T1RSbU1qZ3lOMkV5WXpZMSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJNamN4TTJKaFptWXROVFJtWXkwMFpEWmtMV0kxTlRjdE1tTTNOamMzWXpGaE9HVXoiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTXpBNE9UbGpZakV0TlRZeE5TMDBaV0ZoTFdFMk5HRXRNMk0xT0RNd01tWTFORFJqIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk5tSXdORFJpWXprdFpUSXlNeTAwWlRSbUxXSTRObVV0TjJFM01qTXhPVFppTWpSbSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJaVGc1TmprM1kySXRaVE13TkMwME16VTBMVGd5TkRNdE5HTmtOREJrWkRrM1lUSTMiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWVRVeE5UbGpNRFF0TVRsbFpDMDBZbUkwTFdJMllUUXRPR1psTVRKa01qUTNObVpoIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIll6ZzBZalV6TkRFdE5EazNOaTAwWkRNd0xXRTNNV1V0TmpFelpUSTBaalF3WlRNMCJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJORE0wWWpnd1l6TXRNelE0TUMwME5UaGpMVGswTW1RdE5EVTBPR0l5WWpJNU1HSmsiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTVdZeU1EVmlabU10WWpGaE15MDBabVprTFdFeE5tTXRNall5WmpRM01HTXlNVE01Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIllqRm1ZamxtT1RFdE56TmhZaTAwTW1GaUxUazBOR010Wm1Oak5UUTFPREJqWldZeCJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJNVFZqT0RFek16TXRPREU1TnkwMFlUY3lMVGhoTXpBdFlUUm1PVGc0WTJNeU16STMiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiT0RjeE56RXpaakF0TkRReU5DMDBOV1kzTFdKbFpXSXRNMlptTlRJM1ptTTFOelpsIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk1tUTVOR05tWVdRdE1tVm1NeTAwT0RWakxXRXlNVGN0T0dFMU1UZzNObUk1WmpFNSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJNVFkxWkdZNU5qY3ROekZrTmkwMFlURmpMVGcxWldRdE1HWXpObVUzWmpReE9EVXoiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWTJKaVlqUmlOakV0T0RoaFl5MDBZVFJoTFRneVlUUXRZVGcyTnpRME1qTmlNMll4Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk0yVmpOMlE0WkdFdE5qTXdNUzAwTlRVekxXSTROelV0WW1JNE1qRTVZbVZoTnpsaSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJOakV6WkRNek56QXRaalF3WXkwME9XRTVMV0V4TVdJdFlqTmtNVEZrWmpBME5XWmkiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWm1FMU1XUTFaR010WkRFeVpDMDBOVFZsTFdKalkyTXROelZrWW1GaU5UaGhPVGcxIl19LHsiYWFpZCI6WyJDRDAxIzAwMDEiXSwia2V5SURzIjpbIk5HRmpOekJqWW1VdE1XRTRPQzAwTnpoaExUZzFOakl0TldObFpqVTRaVFU1WXpjMCJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJOalppTmpSbE5tSXRZVE5qTlMwME9XTXlMVGhsTWpBdFlqSTFaalJoWmpNNFpUZzIiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTkRKak5qQmpZbUl0WXpCa1lpMDBNalk1TFRneVpEa3RaakF6WWpGaE9UUmlZekJtIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk5XVmxOREEzTnpFdFptUmlNaTAwT0dVeExXSmpNRFV0WTJSak1tRTBORFV4TkRkaSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJORFUzT0dJM01ESXROVEF3TVMwMFpUQm1MVGt5TkdRdE9EaGtNRFF5TjJOak5qVmgiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWTJaa09UTmlNVFV0TVRGallTMDBPR1F4TFdGaE9HRXRZamt6WVRrd1lXSTJPRGN6Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIll6ZGhaRGRsWlRjdFpURXhOQzAwWlRNNExXSXlOVEV0TUdFNE1UZzBObVJrTW1ReCJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJOelpqTkRZNFlXUXRZVE0yWVMwME1tRmhMVGszTXpjdE1EazJNVFpoTnpreU5UUXgiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWmpReVptVmtZV1F0TmprMVpDMDBOV1ZtTFdJd1pUUXRPR05pTXpNNU1XTTFOemswIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk5qazRPREptTlRNdFl6QXdOUzAwTURZd0xUZ3lOMlV0TVRZM1pqQTROMlkwWVdRNSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJPVEprWldOaU5UQXRZamhsTmkwMFlUVXdMVGswTURVdFlUVTFPR05rTkRZMVpqSTUiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTlRSa1pEUTJPV0l0TlRFM01pMDBOVFl6TFRnMk56RXRObUUwWmpoak1UQTRZek01Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk1XWTBaakF5TW1JdFl6SmxOQzAwTXpjeUxXRXlNVFF0TURNMlltRTNPR0ZqT0dJNSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJORGt6T0RSak9HWXROamd4TmkwME1UYzRMVGd3WVRrdE56aGlZbUV5TkdRek4yUTQiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTlRBeVpUTXpNMlF0WXpJd01pMDBOV1kxTFdJM01EQXRaamd3WVRreFpEVTROekJqIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIllUbGxNREV3TURBdFpUSmxOUzAwTURSa0xXSmxaREV0TXpoa1pXVTVZV1l4WkRJeSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJNR016WmpFeVlUQXRPREl4TUMwMFpHVTNMVGt6TjJRdE5XSTJOVE0xWVdSbE9XUm0iXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTWpsbE5qZzJZell0TURVME9TMDBPVFl3TFRoaE9HWXRPRFkwT1ROa09EZ3habVkyIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIlpXSTBaV0l4TXpndFltWmlNUzAwT0dNM0xXSm1PRFl0T0dRNVpqWTBOVEpsWkRkaiJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJOamhpWTJJek9HSXRaR0ZsT1MwMFlXRXhMV0V6Wm1RdE16UmlNVE5qTXpWalptTmsiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTldNeFlUTTNaalF0TXpWa1lTMDBOVE0yTFRrek5qZ3RNR1F5TVdNNFl6TTVNV0kwIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk4yVTVZalEyTXpjdE5UZzFZUzAwWkdFeExUZzVPVEl0TTJObFlUQmpZVGxoTURBNSJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJabVkyTVRnNFpUQXRZMkkyWXkwME5USmtMV0ptTldVdE1XUmpObVk0TWpCbVl6Qm0iXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiTkdKaFptWXlaRGN0WkRjNE9TMDBZakUzTFRobE1USXRZakk0TmpObVlUZzFOakppIl19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIk56STNZelJoTmpNdE16STVZaTAwT1RrNExUaG1Oamd0TldNd1ltTmhPVEk1WXpNMCJdfSx7ImFhaWQiOlsiMDAzNiMwMDAxIl0sImtleUlEcyI6WyJabVk1TkRFMU5XWXROelJrTnkwMFpUUm1MV0k1TUdRdE9UWmtPV1U0TXpObFkyVmkiXX0seyJhYWlkIjpbIjAwMzYjMDAwMSJdLCJrZXlJRHMiOlsiWVRCaU1XTXlNVGd0WkRSaU5pMDBOVFUzTFdKak5EZ3ROVEUyWldFMU5HWm1aVGN3Il19LHsiYWFpZCI6WyIwMDM2IzAwMDEiXSwia2V5SURzIjpbIllqZzJNVFJoTURjdE0yVXpaQzAwWWpKaUxUZzJaalV0T1Rjek1tTmpNR0k1T1dNMyJdfV1dfX1d\",\"authenticationmode\":\"3\"}";

int main_00(void) {
	json_t *authRequestList_obj;
	json_error_t error;
	json_t *authreq_b64enc = NULL;

	authRequestList_obj = json_loads(S_SAUTHREQ, 0, &error);
	
	if (!authRequestList_obj) {
		fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
		return 1;
	}

	authreq_b64enc = json_object_get(authRequestList_obj, "authrequestmsg");
	if (!json_is_string(authreq_b64enc)) {
		fprintf(stderr, "error: request  is null.\n");
		return 1;
	}
	const char *authrequestmsg_val = json_string_value(authreq_b64enc);

	if (!authrequestmsg_val) {
		fprintf(stderr, "error: authrequestmsg_val  is null.\n");
		return 1;
	}

	char *authreq_b64enc_exten = NULL;

	authreq_b64enc_exten = setExtensionAuthReqB64Url((char *)authrequestmsg_val, (char *)"p_simplekey", (char *)"p_devid", (char *)"p_nonid");

	if (authreq_b64enc_exten) {
		fprintf(stdout, "authreq_b64enc_exten : %s\n", authreq_b64enc_exten);
		extensionAuthReqB64Url_free(authreq_b64enc_exten);
	}
	system("pause");
	return 0;
}

void extensionAuthReqB64Url_free(char *ptr) {
	if (ptr)
		free(ptr);
}

size_t getPubKeyFromAuthReqB64Url(char* p_b64authReq, unsigned char **outPubKey, size_t *outPubKeyLen) {
	size_t retVal = 0;
	size_t ret;
	size_t inlen;
	size_t outlen;
	unsigned char *b64authReq_b64Dec = NULL;
	
	if (p_b64authReq == NULL) {
		fprintf(stderr, "p_b64authReq is NULL.");
		return 1;
	}

	inlen = strlen(p_b64authReq);
	outlen = inlen;
	b64authReq_b64Dec = (unsigned char*)calloc(outlen, sizeof(char));

	ret = Base64Url_Decode((const unsigned char*)p_b64authReq, inlen, b64authReq_b64Dec, &outlen);

	if (ret) {
		fprintf(stderr, "Base64 Decoding Error..");
		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);
		return 1;
	}

	json_t *authRequestRead = NULL;
	json_t *authRequest_dec = NULL;

	json_t *header_dec = NULL;//object
	json_t *challenge_dec = NULL;//string
	json_t *transaction_dec = NULL;//array
	json_t *policy_dec = NULL;//object

	json_t *upv_dec = NULL;
	json_t *op_dec = NULL;
	json_t *appID_dec = NULL;
	json_t *serverData_dec = NULL;
	json_t *exts_dec = NULL;

	json_t *authRequestWriter = NULL;
	json_t *authRequest_enc = NULL;

	json_t *header_enc = NULL;//object

							  //extention 설정
	json_t *exts_list_enc = NULL;
	json_t *exts_enc_simplekey = NULL;
	json_t *exts_enc_devid = NULL;
	json_t *exts_enc_nonid = NULL;

	json_error_t error;
	int authReqSize;
	// json 
	authRequestRead = json_loads((const char*)b64authReq_b64Dec, 0, &error);

	if (!authRequestRead) {
		fprintf(stderr, "error : on line : %d %s\n", error.line, error.text);
		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);
		return 1;
	}

	if (!json_is_array(authRequestRead)) {
		fprintf(stderr, "error : authRequestRead is not Array. : ");
		
		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);

		if (authRequestRead)
			json_decref(authRequestRead);
		return 1;
	}

	authReqSize = json_array_size(authRequestRead);

	fprintf(stdout, "authReqSize : %d", authReqSize);

	if (authReqSize < 1) {
		fprintf(stderr, "error : authRequestRead array size is invalid.");
		
		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);

		if (authRequestRead)
			json_decref(authRequestRead);

		return 1;
	}

	authRequest_dec = json_array_get(authRequestRead, 0);

	if (!json_is_object(authRequest_dec)) {
		fprintf(stderr, "error : authRequest_dec is not object.");

		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);

		if (authRequestRead)
			json_decref(authRequestRead);

		return 1;
	}

	header_dec = json_object_get(authRequest_dec, "header");

	if (!json_is_object(header_dec)) {
		fprintf(stderr, "header_dec is not an object\n");
		
		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);

		if (authRequest_dec)
			json_decref(authRequest_dec);

		if (authRequestRead)
			json_decref(authRequestRead);

		return 1;
	}

	exts_dec = json_object_get(header_dec, "exts");

	if (!json_is_array(exts_dec)) {
		fprintf(stderr, "error : exts_dec is not Array. : ");

		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);

		if (authRequest_dec)
			json_decref(authRequest_dec);

		if (authRequestRead)
			json_decref(authRequestRead);

		return 1;
	}



	return retVal;
}

char* setExtensionAuthReqB64Url(char* p_b64authReq, char* p_simplekey, char* p_devid, char* p_nonid) {
	char* retVal=NULL;
	char* retVal_tmp=NULL;
	size_t retVal_tmp_len;
	size_t inlen;
	size_t outlen;
	size_t ret;
	unsigned char *b64authReq_b64Dec=NULL;
	unsigned char *b64authReq_b64Dec_Tmp = NULL;

	if (p_b64authReq == NULL) {
		fprintf(stderr, "p_b64authReq is NULL.");
		return retVal;
	}

	inlen = strlen(p_b64authReq);
	outlen = inlen;
	b64authReq_b64Dec = (unsigned char*)calloc(outlen,sizeof(char));

	ret = Base64Url_Decode((const unsigned char*)p_b64authReq, inlen, b64authReq_b64Dec, &outlen);

	if (ret) {
		fprintf(stderr, "Base64 Decoding Error..");
		if (b64authReq_b64Dec)
			free(b64authReq_b64Dec);
	}

	b64authReq_b64Dec_Tmp = (unsigned char*)calloc(outlen+1, sizeof(char));

	memcpy(b64authReq_b64Dec_Tmp, b64authReq_b64Dec, outlen);
	
	if (b64authReq_b64Dec)
		free(b64authReq_b64Dec);

	fprintf(stdout, "out : %s\n", (char*)b64authReq_b64Dec_Tmp);
	
	//authentication request message parse

	json_t *authRequestRead = NULL;
	json_t *authRequest_dec = NULL;

	json_t *header_dec = NULL;//object
	json_t *challenge_dec = NULL;//string
	json_t *transaction_dec = NULL;//array
	json_t *policy_dec = NULL;//object

	json_t *upv_dec = NULL;
	json_t *op_dec = NULL;
	json_t *appID_dec = NULL;
	json_t *serverData_dec = NULL;
	json_t *exts_dec = NULL;

	json_t *authRequestWriter = NULL;
	json_t *authRequest_enc = NULL;

	json_t *header_enc = NULL;//object

	//extention 설정
	json_t *exts_list_enc = NULL;
	json_t *exts_enc_simplekey = NULL;
	json_t *exts_enc_devid = NULL;
	json_t *exts_enc_nonid = NULL;

	json_error_t error;
	int authReqSize;
	// json 
	authRequestRead = json_loads((const char*)b64authReq_b64Dec_Tmp, 0, &error);

	if (!authRequestRead) {
		fprintf(stderr, "error : on line : %d %s\n", error.line, error.text);
		goto FINISH;
	}

	if (!json_is_array(authRequestRead)) {
		fprintf(stderr, "error : authRequestRead is not Array. : ");
		goto FINISH;
	}

	authReqSize = json_array_size(authRequestRead);

	fprintf(stdout, "authReqSize : %d", authReqSize);

	if (authReqSize < 1) {
		fprintf(stderr, "error : authRequestRead array size is invalid.");
		goto FINISH;
	}

	authRequest_dec = json_array_get(authRequestRead, 0);

	if (!json_is_object(authRequest_dec)) {
		fprintf(stderr, "error : authRequest_dec is not object.");
		goto FINISH;
	}

	header_dec = json_object_get(authRequest_dec, "header");

	if (!json_is_object(header_dec)) {
		fprintf(stderr, "header_dec is not an object\n");
		goto FINISH;
	}
	
	if (p_simplekey != NULL) {
		exts_enc_simplekey = json_object();
		json_object_set(exts_enc_simplekey, "id", json_string(EXE_SIMPLEPUBKEY));
		json_object_set(exts_enc_simplekey, "data", json_string((const char*)p_simplekey));
		json_object_set(exts_enc_simplekey, "fail_if_unknown", json_boolean(FALSE));

		exts_list_enc = json_array();
		json_array_append(exts_list_enc, exts_enc_simplekey);
	}
	
	if (p_devid != NULL) {
		exts_enc_devid = json_object();
		json_object_set(exts_enc_devid, "id", json_string(EXE_DEVID));
		json_object_set(exts_enc_devid, "data", json_string((const char*)p_devid));
		json_object_set(exts_enc_devid, "fail_if_unknown", json_boolean(FALSE));

		if (exts_list_enc == NULL) {
			exts_list_enc = json_array();
		}
		json_array_append(exts_list_enc, exts_enc_devid);
	}
	
	if (p_nonid != NULL) {
		exts_enc_nonid = json_object();
		json_object_set(exts_enc_nonid, "id", json_string(EXE_NONID));
		json_object_set(exts_enc_nonid, "data", json_string((const char*)p_nonid));
		json_object_set(exts_enc_nonid, "fail_if_unknown", json_boolean(FALSE));

		if (exts_list_enc == NULL) {
			exts_list_enc = json_array();
		}
		json_array_append(exts_list_enc, exts_enc_nonid);
	}

	challenge_dec = json_object_get(authRequest_dec, "challenge");
	transaction_dec = json_object_get(authRequest_dec, "transaction");//array
	policy_dec = json_object_get(authRequest_dec, "policy");//policy

	upv_dec = json_object_get(header_dec, "upv");
	op_dec = json_object_get(header_dec, "op");
	appID_dec = json_object_get(header_dec, "appID");
	serverData_dec = json_object_get(header_dec, "serverData");
	exts_dec = json_object_get(header_dec, "exts");

	//authentication request 메시지 재설정
	authRequestWriter = json_array();
	authRequest_enc = json_object();

	header_enc = json_object();;//object
	
	if(json_is_object(upv_dec)){
		json_object_set(header_enc, "upv", upv_dec);
	}
	
	if(json_is_string(op_dec)){
		json_object_set(header_enc, "op", op_dec);
	}

	if(json_is_string(appID_dec)){
		json_object_set(header_enc, "appID", appID_dec);
	}

	if(json_is_string(serverData_dec)){
		json_object_set(header_enc, "serverData", serverData_dec);
	}

	if (exts_list_enc != NULL) {
		json_object_set(header_enc, "exts", exts_list_enc);
	}
	
	json_object_set(authRequest_enc, "header", header_enc);
	json_object_set(authRequest_enc, "challenge", challenge_dec);
	json_object_set(authRequest_enc, "transaction", transaction_dec);
	json_object_set(authRequest_enc, "policy", policy_dec);
	json_array_append(authRequestWriter, authRequest_enc);

	retVal_tmp = json_dumps(authRequestWriter, 0);

	if (retVal_tmp == NULL) {
		fprintf(stderr, "retVal_tmp is NULL.\n");
		goto FINISH;
	}

	retVal_tmp_len = strlen(retVal_tmp);
	retVal = (char*)calloc(retVal_tmp_len + 1, sizeof(char));
	
	memcpy(retVal, retVal_tmp, retVal_tmp_len);

FINISH :
	if (retVal_tmp)
		free(retVal_tmp);

	if (upv_dec)
		json_decref(upv_dec);

	if(op_dec)
		json_decref(op_dec);

	if(appID_dec)
		json_decref(appID_dec);

	if(serverData_dec)
		json_decref(serverData_dec);

	if(exts_dec)
		json_decref(exts_dec);

	if (authRequest_dec)
		json_decref(authRequest_dec);

	if (authRequestRead)
		json_decref(authRequestRead);

	if (exts_enc_nonid)
		json_decref(exts_enc_nonid);

	if(exts_enc_devid)
		json_decref(exts_enc_devid);

	if(exts_enc_simplekey)
		json_decref(exts_enc_simplekey);

	if(exts_list_enc)
		json_decref(exts_list_enc);

	if(header_enc)
		json_decref(header_enc);

	if(authRequest_enc)
		json_decref(authRequest_enc);

	if(authRequestWriter)
		json_decref(authRequestWriter);

	return retVal;
}