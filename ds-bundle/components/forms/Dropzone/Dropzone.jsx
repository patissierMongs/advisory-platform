import { Dropzone, Card } from "advisory-platform-ds";


export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 24 }}>
      <Card padding="24px">
        <Dropzone
          title="PDF 파일을 여기로 끌어다 놓으세요"
          hint="또는 클릭하여 파일 선택 · 최대 30MB · 다중 업로드 지원"
          buttonLabel="파일 선택"
        />
      </Card>
    </div>
  );
}
