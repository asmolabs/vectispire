import { crc32, deflateRawSync } from 'node:zlib';

/**
 * A checklist workbook written part by part, from invented controls — never a real template, whose
 * content is its organisation's (decision 0032), the same rule the backend's `XlsxFixture` follows.
 *
 * <p>The smallest the reader accepts: a workbook part, one sheet, inline strings. A product header
 * in A1/B1, the column heads in row 3, three items in rows 4 to 6, the domain filled down.
 */
export function checklistWorkbook(): Buffer {
    const MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
    const REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
    const PACKAGE_REL = 'http://schemas.openxmlformats.org/package/2006/relationships';
    const text = (ref: string, value: string) => `<c r="${ref}" t="inlineStr"><is><t>${value}</t></is></c>`;
    const row = (number: number, cells: string) => `<row r="${number}">${cells}</row>`;
    const rows =
        row(1, text('A1', 'Product')) +
        row(3, text('A3', 'Domain') + text('B3', 'Control') + text('C3', 'Answer') + text('D3', 'Comment')) +
        row(4, text('A4', 'Identity') + text('B4', 'Every account belongs to one named person.')) +
        row(5, text('B5', 'Shared accounts are disabled.')) +
        row(6, text('A6', 'Supply chain') + text('B6', 'Every build publishes an SBOM.'));

    return zip({
        '[Content_Types].xml':
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
            '<Default Extension="xml" ContentType="application/xml"/>' +
            '<Override PartName="/xl/workbook.xml" ' +
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
            '<Override PartName="/xl/worksheets/sheet1.xml" ' +
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
            '</Types>',
        '_rels/.rels':
            `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="${PACKAGE_REL}">` +
            `<Relationship Id="rId1" Type="${REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
        'xl/workbook.xml':
            `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="${MAIN}" xmlns:r="${REL}">` +
            '<sheets><sheet name="Checklist" sheetId="1" r:id="rId1"/></sheets></workbook>',
        'xl/_rels/workbook.xml.rels':
            `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="${PACKAGE_REL}">` +
            `<Relationship Id="rId1" Type="${REL}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
        'xl/worksheets/sheet1.xml':
            `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="${MAIN}" xmlns:r="${REL}">` +
            `<sheetData>${rows}</sheetData></worksheet>`
    });
}

/** A zip of deflated entries — local headers, central directory, end record — in the order given. */
function zip(parts: Record<string, string>): Buffer {
    const locals: Buffer[] = [];
    const centrals: Buffer[] = [];
    let offset = 0;
    for (const [name, content] of Object.entries(parts)) {
        const raw = Buffer.from(content, 'utf8');
        const deflated = deflateRawSync(raw);
        const fileName = Buffer.from(name, 'utf8');
        const crc = crc32(raw);

        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);
        local.writeUInt16LE(8, 8); // deflate
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(deflated.length, 18);
        local.writeUInt32LE(raw.length, 22);
        local.writeUInt16LE(fileName.length, 26);
        locals.push(local, fileName, deflated);

        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0);
        central.writeUInt16LE(20, 4);
        central.writeUInt16LE(20, 6);
        central.writeUInt16LE(8, 10);
        central.writeUInt32LE(crc, 16);
        central.writeUInt32LE(deflated.length, 20);
        central.writeUInt32LE(raw.length, 24);
        central.writeUInt16LE(fileName.length, 28);
        central.writeUInt32LE(offset, 42);
        centrals.push(central, fileName);

        offset += local.length + fileName.length + deflated.length;
    }
    const directory = Buffer.concat(centrals);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(Object.keys(parts).length, 8);
    end.writeUInt16LE(Object.keys(parts).length, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...locals, directory, end]);
}
