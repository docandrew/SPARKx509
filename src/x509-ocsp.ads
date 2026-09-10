--  X509.OCSP -- OCSP response parser (RFC 6960 section 4.2)
--
--  Parses a DER OCSPResponse into an OCSP_View: the response status,
--  and when it is successful the BasicOCSPResponse fields a verifier
--  needs -- the tbsResponseData span the signature covers, the
--  responder ID, producedAt, the signature, up to Max_Single_Responses
--  SingleResponses (CertID + status + validity window) and the spans of
--  up to Max_Embedded_Certs certificates from the optional certs field.
--
--  Parser only. Signature verification, responder authorization
--  (RFC 6960 4.2.2.2), CertID matching and freshness live in
--  SPARKTLS.Revocation. Only id-pkix-ocsp-basic responses are
--  understood; any other responseType fails the parse.

package X509.OCSP with
   SPARK_Mode => On
is
   --  OCSPResponseStatus (4.2.1). Unknown_Status = a value outside the
   --  enumeration (the response is still well-formed).
   type Response_Status is
     (Successful, Malformed_Request, Internal_Error, Try_Later,
      Sig_Required, Unauthorized, Unknown_Status);

   --  CertStatus CHOICE (4.2.2.3)
   type Cert_Status is (Status_Good, Status_Revoked, Status_Unknown);

   --  CertID.hashAlgorithm (4.1.1). SHA-1 is what responders use in
   --  practice (RFC 5019 2.1.1); SHA-256 is permitted by RFC 6960 4.3.
   type Hash_Algorithm is
     (Hash_Unknown, Hash_SHA1, Hash_SHA256, Hash_SHA384, Hash_SHA512);

   --  ResponderID CHOICE (4.2.2.1)
   type Responder_ID_Kind is (Responder_None, Responder_By_Name, Responder_By_Key);

   Max_Single_Responses : constant := 8;
   Max_Embedded_Certs   : constant := 4;

   --  SingleResponse (4.2.2.3). Spans point into the response DER.
   --  S_Issuer_Name_Hash / S_Issuer_Key_Hash are the OCTET STRING
   --  contents; S_Serial is the INTEGER content (compare byte-for-byte
   --  against X509.Serial (Cert) in the certificate's DER).
   type Single_Response is record
      Hash_Algo          : Hash_Algorithm := Hash_Unknown;
      S_Issuer_Name_Hash : Span;
      S_Issuer_Key_Hash  : Span;
      S_Serial           : Span;
      Status             : Cert_Status    := Status_Unknown;
      This_Update        : Date_Time;
      Has_Next_Update    : Boolean        := False;
      Next_Update        : Date_Time;
      --  Only meaningful when Status = Status_Revoked
      Revocation_Time    : Date_Time;
      Has_Reason         : Boolean        := False;
      Reason             : Natural        := 0;
      --  A critical singleExtension this parser does not recognize
      Unknown_Critical   : Boolean        := False;
   end record;

   function Single_Spans_Valid
     (R : Single_Response; DER_Last : N32) return Boolean
   is (Span_In_Range (R.S_Issuer_Name_Hash, DER_Last)
       and then Span_In_Range (R.S_Issuer_Key_Hash, DER_Last)
       and then Span_In_Range (R.S_Serial, DER_Last));

   type OCSP_View is private;

   function Is_Valid (V : OCSP_View) return Boolean;
   function Spans_Valid (V : OCSP_View; DER_Last : N32) return Boolean;

   procedure Parse
     (DER : in     Byte_Seq;
      V   :    out OCSP_View;
      OK  :    out Boolean)
   with Pre  => DER'First = 0 and DER'Last < N32'Last,
        Post => (if OK then Is_Valid (V) and Spans_Valid (V, DER'Last));

   function Status (V : OCSP_View) return Response_Status;

   --  True when Status = Successful and a BasicOCSPResponse was parsed.
   --  All getters below are only meaningful when this holds.
   function Has_Basic_Response (V : OCSP_View) return Boolean;

   --  Full tbsResponseData TLV: the bytes the signature covers.
   function TBS (V : OCSP_View) return Span;

   --  ResponseData.version (v1 = 1)
   function Version (V : OCSP_View) return Natural;

   --  byName: content of the responder Name SEQUENCE (compare with the
   --  candidate signer's subject). byKey: the 20-byte KeyHash content
   --  (SHA-1 of the signer's subjectPublicKey BIT STRING content).
   function Responder_Kind (V : OCSP_View) return Responder_ID_Kind;
   function Responder_ID   (V : OCSP_View) return Span;

   function Produced_At (V : OCSP_View) return Date_Time;

   function Sig_Algorithm (V : OCSP_View) return Algorithm_ID;
   function Sig_Length    (V : OCSP_View) return N32;
   function Sig_Data      (V : OCSP_View) return Byte_Seq
   with Pre  => Sig_Length (V) > 0 and Sig_Length (V) <= Max_Sig_Bytes,
        Post => Sig_Data'Result'First = 0
                and Sig_Data'Result'Length = Sig_Length (V);

   --  Stored SingleResponses (at most Max_Single_Responses) and the
   --  total number present in the response.
   function Response_Count       (V : OCSP_View) return Natural;
   function Total_Response_Count (V : OCSP_View) return N32;
   function Get_Response
     (V : OCSP_View; Index : Positive) return Single_Response
   with Pre  => Index <= Response_Count (V)
                and Response_Count (V) <= Max_Single_Responses,
        Post => (for all L in N32 =>
                   (if Spans_Valid (V, L)
                    then Single_Spans_Valid (Get_Response'Result, L)));

   --  certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL: spans of the
   --  full Certificate TLVs (parse each with X509.Parse after copying
   --  into a zero-based buffer).
   function Embedded_Cert_Count (V : OCSP_View) return Natural;
   function Embedded_Cert
     (V : OCSP_View; Index : Positive) return Span
   with Pre  => Index <= Embedded_Cert_Count (V)
                and Embedded_Cert_Count (V) <= Max_Embedded_Certs,
        Post => (for all L in N32 =>
                   (if Spans_Valid (V, L)
                    then Span_In_Range (Embedded_Cert'Result, L)));

   --  id-pkix-ocsp-nonce (4.4.1) response extension, extnValue content
   function Has_Nonce (V : OCSP_View) return Boolean;
   function Nonce     (V : OCSP_View) return Span;

   --  A critical responseExtension this parser does not recognize
   function Has_Unknown_Critical_Extension (V : OCSP_View) return Boolean;

private

   type Response_Array is
     array (1 .. Max_Single_Responses) of Single_Response;
   type Cert_Span_Array is
     array (1 .. Max_Embedded_Certs) of Span;

   subtype Response_Count_T is Natural range 0 .. Max_Single_Responses;
   subtype Cert_Count_T     is Natural range 0 .. Max_Embedded_Certs;

   type OCSP_View is record
      Valid_Flag      : Boolean           := False;
      Resp_Status     : Response_Status   := Unknown_Status;
      Has_Basic       : Boolean           := False;
      Resp_Version    : Natural           := 1;

      S_TBS           : Span;
      Resp_Kind       : Responder_ID_Kind := Responder_None;
      S_Responder     : Span;
      Produced        : Date_Time;

      Sig_Algo        : Algorithm_ID      := Algo_Unknown;
      Sig_Buf         : Byte_Seq (0 .. Max_Sig_Bytes - 1) := (others => 0);
      Sig_Buf_Len     : N32               := 0;

      Responses       : Response_Array;
      Resp_Num        : Response_Count_T  := 0;
      Resp_Total      : N32               := 0;

      Certs           : Cert_Span_Array   := (others => (0, 0, False));
      Cert_Num        : Cert_Count_T      := 0;

      S_Nonce         : Span;
      Unknown_Crit    : Boolean           := False;
   end record;

   function Spans_Valid (V : OCSP_View; DER_Last : N32) return Boolean is
     (Span_In_Range (V.S_TBS, DER_Last)
      and then Span_In_Range (V.S_Responder, DER_Last)
      and then Span_In_Range (V.S_Nonce, DER_Last)
      and then (for all I in 1 .. Max_Single_Responses =>
                  Single_Spans_Valid (V.Responses (I), DER_Last))
      and then (for all I in 1 .. Max_Embedded_Certs =>
                  Span_In_Range (V.Certs (I), DER_Last)));

   function Is_Valid (V : OCSP_View) return Boolean is (V.Valid_Flag);

end X509.OCSP;
