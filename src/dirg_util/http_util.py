# -*- coding: utf-8 -*-
#
# Copyright (C) Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import cgi
import time
import hashlib
import hmac
import json
import string
from urlparse import parse_qs
from StringIO import StringIO
from Cookie import SimpleCookie
from urllib import quote

from Crypto.Random import random

from dirg_util import time_util
from dirg_util.aes import AESCipher


class UnsupportedMethod(Exception):
    pass


class HttpHandler:
    GLOBAL_STATIC = "/opt/dirg/dirg-util/"

    mime_map = {'x-conference': {
    '.ice': {'file_end': '.ice', 'type': 'x-conference/x-cooltalk', 'name': 'x-conference', 'description': 'CoolTalk'}},
                'text': {'.flx': {'file_end': '.flx', 'type': 'text/vnd.fmi.flexstor', 'name': 'text',
                                  'description': 'FLEXSTOR'},
                         '.fly': {'file_end': '.fly', 'type': 'text/vnd.fly', 'name': 'text',
                                  'description': 'mod_fly / fly.cgi'},
                         '.dsc': {'file_end': '.dsc', 'type': 'text/prs.lines.tag', 'name': 'text',
                                  'description': 'PRS Lines Tag'},
                         '.mcurl': {'file_end': '.mcurl', 'type': 'text/vnd.curl.mcurl', 'name': 'text',
                                    'description': 'Curl - Manifest File'},
                         '.n3': {'file_end': '.n3', 'type': 'text/n3', 'name': 'text', 'description': 'Notation3'},
                         '.dcurl': {'file_end': '.dcurl', 'type': 'text/vnd.curl.dcurl', 'name': 'text',
                                    'description': 'Curl - Detached Applet'},
                         '.par': {'file_end': '.par', 'type': 'text/plain-bas', 'name': 'text',
                                  'description': 'BAS Partitur Format'},
                         '.rtx': {'file_end': '.rtx', 'type': 'text/richtext', 'name': 'text',
                                  'description': 'Rich Text Format (RTF)'},
                         '.tsv': {'file_end': '.tsv', 'type': 'text/tab-separated-values', 'name': 'text',
                                  'description': 'Tab Seperated Values'},
                         '.vcs': {'file_end': '.vcs', 'type': 'text/x-vcalendar', 'name': 'text',
                                  'description': 'vCalendar'},
                         '.sgml': {'file_end': '.sgml', 'type': 'text/sgml', 'name': 'text',
                                   'description': 'Standard Generalized Markup Language (SGML)'},
                         '.scurl': {'file_end': '.scurl', 'type': 'text/vnd.curl.scurl', 'name': 'text',
                                    'description': 'Curl - Source Code'},
                         '.uri': {'file_end': '.uri', 'type': 'text/uri-list', 'name': 'text',
                                  'description': 'URI Resolution Services'},
                         '.ttl': {'file_end': '.ttl', 'type': 'text/turtle', 'name': 'text',
                                  'description': 'Turtle (Terse RDF Triple Language)'},
                         '.uu': {'file_end': '.uu', 'type': 'text/x-uuencode', 'name': 'text',
                                 'description': 'UUEncode'},
                         '.spot': {'file_end': '.spot', 'type': 'text/vnd.in3d.spot', 'name': 'text',
                                   'description': 'In3D - 3DML'},
                         '.wmls': {'file_end': '.wmls', 'type': 'text/vnd.wap.wmlscript', 'name': 'text',
                                   'description': 'Wireless Markup Language Script (WMLScript)'},
                         '.p': {'file_end': '.p', 'type': 'text/x-pascal', 'name': 'text',
                                'description': 'Pascal Source File'},
                         '.jad': {'file_end': '.jad', 'type': 'text/vnd.sun.j2me.app-descriptor', 'name': 'text',
                                  'description': 'J2ME App Descriptor'},
                         '.etx': {'file_end': '.etx', 'type': 'text/x-setext', 'name': 'text', 'description': 'Setext'},
                         '.curl': {'file_end': '.curl', 'type': 'text/vnd.curl', 'name': 'text',
                                   'description': 'Curl - Applet'},
                         '.java': {'file_end': '.java', 'type': 'text/x-java-source,java', 'name': 'text',
                                   'description': 'Java Source File'},
                         '.wml': {'file_end': '.wml', 'type': 'text/vnd.wap.wml', 'name': 'text',
                                  'description': 'Wireless Markup Language (WML)'},
                         '.vcf': {'file_end': '.vcf', 'type': 'text/x-vcard', 'name': 'text', 'description': 'vCard'},
                         '.ics': {'file_end': '.ics', 'type': 'text/calendar', 'name': 'text',
                                  'description': 'iCalendar'},
                         '.csv': {'file_end': '.csv', 'type': 'text/csv', 'name': 'text',
                                  'description': 'Comma-Seperated Values'},
                         '.c': {'file_end': '.c', 'type': 'text/x-c', 'name': 'text', 'description': 'C Source File'},
                         '.f': {'file_end': '.f', 'type': 'text/x-fortran', 'name': 'text',
                                'description': 'Fortran Source File'},
                         '.css': {'file_end': '.css', 'type': 'text/css', 'name': 'text',
                                  'description': 'Cascading Style Sheets (CSS)'},
                         '.gv': {'file_end': '.gv', 'type': 'text/vnd.graphviz', 'name': 'text',
                                 'description': 'Graphviz'},
                         '.txt': {'file_end': '.txt', 'type': 'text/plain', 'name': 'text', 'description': 'Text File'},
                         '.3dml': {'file_end': '.3dml', 'type': 'text/vnd.in3d.3dml', 'name': 'text',
                                   'description': 'In3D - 3DML'},
                         '.html': {'file_end': '.html', 'type': 'text/html', 'name': 'text',
                                   'description': 'HyperText Markup Language (HTML)'},
                         '.s': {'file_end': '.s', 'type': 'text/x-asm', 'name': 'text',
                                'description': 'Assembler Source File'},
                         '.t': {'file_end': '.t', 'type': 'text/troff', 'name': 'text', 'description': 'troff'}},
                'image': {'.wbmp': {'file_end': '.wbmp', 'type': 'image/vnd.wap.wbmp', 'name': 'image',
                                    'description': 'WAP Bitamp (WBMP)'},
                          '.btif': {'file_end': '.btif', 'type': 'image/prs.btif', 'name': 'image',
                                    'description': 'BTIF'},
                          '.fbs': {'file_end': '.fbs', 'type': 'image/vnd.fastbidsheet', 'name': 'image',
                                   'description': 'FastBid Sheet'},
                          '.cmx': {'file_end': '.cmx', 'type': 'image/x-cmx', 'name': 'image',
                                   'description': 'Corel Metafile Exchange (CMX)'},
                          '.rgb': {'file_end': '.rgb', 'type': 'image/x-rgb', 'name': 'image',
                                   'description': 'Silicon Graphics RGB Bitmap'},
                          '.dwg': {'file_end': '.dwg', 'type': 'image/vnd.dwg', 'name': 'image',
                                   'description': 'DWG Drawing'},
                          '.fst': {'file_end': '.fst', 'type': 'image/vnd.fst', 'name': 'image',
                                   'description': 'FAST Search & Transfer ASA'},
                          '.pcx': {'file_end': '.pcx', 'type': 'image/x-pcx', 'name': 'image',
                                   'description': 'PCX Image'},
                          '.mdi': {'file_end': '.mdi', 'type': 'image/vnd.ms-modi', 'name': 'image',
                                   'description': 'Microsoft Document Imaging Format'},
                          '.xif': {'file_end': '.xif', 'type': 'image/vnd.xiff', 'name': 'image',
                                   'description': 'eXtended Image File Format (XIFF)'},
                          '.xpm': {'file_end': '.xpm', 'type': 'image/x-xpixmap', 'name': 'image',
                                   'description': 'X PixMap'},
                          '.gif': {'file_end': '.gif', 'type': 'image/gif', 'name': 'image',
                                   'description': 'Graphics Interchange Format'},
                          '.ras': {'file_end': '.ras', 'type': 'image/x-cmu-raster', 'name': 'image',
                                   'description': 'CMU Image'},
                          '.pic': {'file_end': '.pic', 'type': 'image/x-pict', 'name': 'image',
                                   'description': 'PICT Image'},
                          '.fh': {'file_end': '.fh', 'type': 'image/x-freehand', 'name': 'image',
                                  'description': 'FreeHand MX'},
                          '.djvu': {'file_end': '.djvu', 'type': 'image/vnd.djvu', 'name': 'image',
                                    'description': 'DjVu'},
                          '.ppm': {'file_end': '.ppm', 'type': 'image/x-portable-pixmap', 'name': 'image',
                                   'description': 'Portable Pixmap Format'},
                          '.svg': {'file_end': '.svg', 'type': 'image/svg+xml', 'name': 'image',
                                   'description': 'Scalable Vector Graphics (SVG)'},
                          '.g3': {'file_end': '.g3', 'type': 'image/g3fax', 'name': 'image',
                                  'description': 'G3 Fax Image'},
                          '.cgm': {'file_end': '.cgm', 'type': 'image/cgm', 'name': 'image',
                                   'description': 'Computer Graphics Metafile'},
                          '.mmr': {'file_end': '.mmr', 'type': 'image/vnd.fujixerox.edmics-mmr', 'name': 'image',
                                   'description': 'EDMICS 2000'},
                          '.xbm': {'file_end': '.xbm', 'type': 'image/x-xbitmap', 'name': 'image',
                                   'description': 'X BitMap'},
                          '.xwd': {'file_end': '.xwd', 'type': 'image/x-xwindowdump', 'name': 'image',
                                   'description': 'X Window Dump'},
                          '.ief': {'file_end': '.ief', 'type': 'image/ief', 'name': 'image',
                                   'description': 'Image Exchange Format'},
                          '.webp': {'file_end': '.webp', 'type': 'image/webp', 'name': 'image',
                                    'description': 'WebP Image'},
                          '.bmp': {'file_end': '.bmp', 'type': 'image/bmp', 'name': 'image',
                                   'description': 'Bitmap Image File'},
                          '.uvi': {'file_end': '.uvi', 'type': 'image/vnd.dece.graphic', 'name': 'image',
                                   'description': 'DECE Graphic'},
                          '.pbm': {'file_end': '.pbm', 'type': 'image/x-portable-bitmap', 'name': 'image',
                                   'description': 'Portable Bitmap Format'},
                          '.pgm': {'file_end': '.pgm', 'type': 'image/x-portable-graymap', 'name': 'image',
                                   'description': 'Portable Graymap Format'},
                          '.fpx': {'file_end': '.fpx', 'type': 'image/vnd.fpx', 'name': 'image',
                                   'description': 'FlashPix'},
                          '.png': {'file_end': '.png', 'type': 'image/png', 'name': 'image',
                                   'description': 'Portable Network Graphics (PNG)'},
                          '.npx': {'file_end': '.npx', 'type': 'image/vnd.net-fpx', 'name': 'image',
                                   'description': 'FlashPix'},
                          '.pnm': {'file_end': '.pnm', 'type': 'image/x-portable-anymap', 'name': 'image',
                                   'description': 'Portable Anymap Image'},
                          '.rlc': {'file_end': '.rlc', 'type': 'image/vnd.fujixerox.edmics-rlc', 'name': 'image',
                                   'description': 'EDMICS 2000'},
                          '.jpeg, .jpg': {'file_end': '.jpeg, .jpg', 'type': 'image/jpeg', 'name': 'image',
                                          'description': 'JPEG Image'},
                          '.dxf': {'file_end': '.dxf', 'type': 'image/vnd.dxf', 'name': 'image',
                                   'description': 'AutoCAD DXF'},
                          '.ico': {'file_end': '.ico', 'type': 'image/x-icon', 'name': 'image',
                                   'description': 'Icon Image'},
                          '.psd': {'file_end': '.psd', 'type': 'image/vnd.adobe.photoshop', 'name': 'image',
                                   'description': 'Photoshop Document'},
                          '.ktx': {'file_end': '.ktx', 'type': 'image/ktx', 'name': 'image',
                                   'description': 'OpenGL Textures (KTX)'},
                          '.sub': {'file_end': '.sub', 'type': 'image/vnd.dvb.subtitle', 'name': 'image',
                                   'description': 'Close Captioning - Subtitle'},
                          '.tiff': {'file_end': '.tiff', 'type': 'image/tiff', 'name': 'image',
                                    'description': 'Tagged Image File Format'}}, 'chemical': {
    '.cdx': {'file_end': '.cdx', 'type': 'chemical/x-cdx', 'name': 'chemical', 'description': 'ChemDraw eXchange file'},
    '.cml': {'file_end': '.cml', 'type': 'chemical/x-cml', 'name': 'chemical',
             'description': 'Chemical Markup Language'},
    '.cmdf': {'file_end': '.cmdf', 'type': 'chemical/x-cmdf', 'name': 'chemical',
              'description': 'CrystalMaker Data Format'},
    '.xyz': {'file_end': '.xyz', 'type': 'chemical/x-xyz', 'name': 'chemical', 'description': 'XYZ File Format'},
    '.cif': {'file_end': '.cif', 'type': 'chemical/x-cif', 'name': 'chemical',
             'description': 'Crystallographic Interchange Format'},
    '.csml': {'file_end': '.csml', 'type': 'chemical/x-csml', 'name': 'chemical',
              'description': 'Chemical Style Markup Language'}}, 'application': {
    '': {'file_end': '', 'type': 'application/pgp-encrypted', 'name': 'application',
         'description': 'Pretty Good Privacy'},
    '.obd': {'file_end': '.obd', 'type': 'application/x-msbinder', 'name': 'application',
             'description': 'Microsoft Office Binder'},
    '.dfac': {'file_end': '.dfac', 'type': 'application/vnd.dreamfactory', 'name': 'application',
              'description': 'DreamFactory'},
    '.cryptonote': {'file_end': '.cryptonote', 'type': 'application/vnd.rig.cryptonote', 'name': 'application',
                    'description': 'CryptoNote'},
    '.pml': {'file_end': '.pml', 'type': 'application/vnd.ctc-posml', 'name': 'application', 'description': 'PosML'},
    '.rl': {'file_end': '.rl', 'type': 'application/resource-lists+xml', 'name': 'application',
            'description': 'XML Resource Lists'},
    '.rar': {'file_end': '.rar', 'type': 'application/x-rar-compressed', 'name': 'application',
             'description': 'RAR Archive'},
    '.mrc': {'file_end': '.mrc', 'type': 'application/marc', 'name': 'application', 'description': 'MARC Formats'},
    '.bcpio': {'file_end': '.bcpio', 'type': 'application/x-bcpio', 'name': 'application',
               'description': 'Binary CPIO Archive'},
    '.sdkm': {'file_end': '.sdkm', 'type': 'application/vnd.solent.sdkm+xml', 'name': 'application',
              'description': 'SudokuMagic'},
    '.bz': {'file_end': '.bz', 'type': 'application/x-bzip', 'name': 'application', 'description': 'Bzip Archive'},
    '.rss, .xml': {'file_end': '.rss, .xml', 'type': 'application/rss+xml', 'name': 'application',
                   'description': 'RSS - Really Simple Syndication'},
    '.ait': {'file_end': '.ait', 'type': 'application/vnd.dvb.ait', 'name': 'application',
             'description': 'Digital Video Broadcasting'},
    '.vsf': {'file_end': '.vsf', 'type': 'application/vnd.vsf', 'name': 'application', 'description': 'Viewport+'},
    '.geo': {'file_end': '.geo', 'type': 'application/vnd.dynageo', 'name': 'application', 'description': 'DynaGeo'},
    '.air': {'file_end': '.air', 'type': 'application/vnd.adobe.air-application-installer-package+zip',
             'name': 'application', 'description': 'Adobe AIR Application'},
    '.bmi': {'file_end': '.bmi', 'type': 'application/vnd.bmi', 'name': 'application',
             'description': 'BMI Drawing Data Interchange'},
    '.dvi': {'file_end': '.dvi', 'type': 'application/x-dvi', 'name': 'application',
             'description': 'Device Independent File Format (DVI)'},
    '.gex': {'file_end': '.gex', 'type': 'application/vnd.geometry-explorer', 'name': 'application',
             'description': 'GeoMetry Explorer'},
    '.grxml': {'file_end': '.grxml', 'type': 'application/srgs+xml', 'name': 'application',
               'description': 'Speech Recognition Grammar Specification - XML'},
    '.hpid': {'file_end': '.hpid', 'type': 'application/vnd.hp-hpid', 'name': 'application',
              'description': 'Hewlett Packard Instant Delivery'},
    '.ott': {'file_end': '.ott', 'type': 'application/vnd.oasis.opendocument.text-template', 'name': 'application',
             'description': 'OpenDocument Text Template'},
    '.otp': {'file_end': '.otp', 'type': 'application/vnd.oasis.opendocument.presentation-template',
             'name': 'application', 'description': 'OpenDocument Presentation Template'},
    '.ots': {'file_end': '.ots', 'type': 'application/vnd.oasis.opendocument.spreadsheet-template',
             'name': 'application', 'description': 'OpenDocument Spreadsheet Template'},
    '.atom, .xml': {'file_end': '.atom, .xml', 'type': 'application/atom+xml', 'name': 'application',
                    'description': 'Atom Syndication Format'},
    '.p10': {'file_end': '.p10', 'type': 'application/pkcs10', 'name': 'application',
             'description': 'PKCS #10 - Certification Request Standard'},
    '.nml': {'file_end': '.nml', 'type': 'application/vnd.enliven', 'name': 'application',
             'description': 'Enliven Viewer'},
    '.csp': {'file_end': '.csp', 'type': 'application/vnd.commonspace', 'name': 'application',
             'description': 'Sixth Floor Media - CommonSpace'},
    '.sus': {'file_end': '.sus', 'type': 'application/vnd.sus-calendar', 'name': 'application',
             'description': 'ScheduleUs'},
    '.g3w': {'file_end': '.g3w', 'type': 'application/vnd.geospace', 'name': 'application', 'description': 'GeospacW'},
    '.otg': {'file_end': '.otg', 'type': 'application/vnd.oasis.opendocument.graphics-template', 'name': 'application',
             'description': 'OpenDocument Graphics Template'},
    '.otf': {'file_end': '.otf', 'type': 'application/x-font-otf', 'name': 'application',
             'description': 'OpenType Font File'},
    '.csh': {'file_end': '.csh', 'type': 'application/x-csh', 'name': 'application', 'description': 'C Shell Script'},
    '.bdf': {'file_end': '.bdf', 'type': 'application/x-font-bdf', 'name': 'application',
             'description': 'Glyph Bitmap Distribution Format'},
    '.pdb': {'file_end': '.pdb', 'type': 'application/vnd.palm', 'name': 'application', 'description': 'PalmOS Data'},
    '.pdf': {'file_end': '.pdf', 'type': 'application/pdf', 'name': 'application',
             'description': 'Adobe Portable Document Format'},
    '.es': {'file_end': '.es', 'type': 'application/ecmascript', 'name': 'application', 'description': 'ECMAScript'},
    '.atomsvc': {'file_end': '.atomsvc', 'type': 'application/atomsvc+xml', 'name': 'application',
                 'description': 'Atom Publishing Protocol Service Document'},
    '.xul': {'file_end': '.xul', 'type': 'application/vnd.mozilla.xul+xml', 'name': 'application',
             'description': 'XUL - XML User Interface Language'},
    '.chm': {'file_end': '.chm', 'type': 'application/vnd.ms-htmlhelp', 'name': 'application',
             'description': 'Microsoft Html Help File'},
    '.xml': {'file_end': '.xml', 'type': 'application/xml', 'name': 'application',
             'description': 'XML - Extensible Markup Language'},
    '.umj': {'file_end': '.umj', 'type': 'application/vnd.umajin', 'name': 'application', 'description': 'UMAJIN'},
    '.fig': {'file_end': '.fig', 'type': 'application/x-xfig', 'name': 'application', 'description': 'Xfig'},
    '.cab': {'file_end': '.cab', 'type': 'application/vnd.ms-cab-compressed', 'name': 'application',
             'description': 'Microsoft Cabinet File'},
    '.ltf': {'file_end': '.ltf', 'type': 'application/vnd.frogans.ltf', 'name': 'application',
             'description': 'Frogans Player'},
    '.sis': {'file_end': '.sis', 'type': 'application/vnd.symbian.install', 'name': 'application',
             'description': 'Symbian Install Package'},
    '.prc': {'file_end': '.prc', 'type': 'application/x-mobipocket-ebook', 'name': 'application',
             'description': 'Mobipocket'},
    '.pre': {'file_end': '.pre', 'type': 'application/vnd.lotus-freelance', 'name': 'application',
             'description': 'Lotus Freelance'},
    '.prf': {'file_end': '.prf', 'type': 'application/pics-rules', 'name': 'application', 'description': 'PICSRules'},
    '.car': {'file_end': '.car', 'type': 'application/vnd.curl.car', 'name': 'application',
             'description': 'CURL Applet'},
    '.tsd': {'file_end': '.tsd', 'type': 'application/timestamped-data', 'name': 'application',
             'description': 'Time Stamped Data Envelope'},
    '.dd2': {'file_end': '.dd2', 'type': 'application/vnd.oma.dd2+xml', 'name': 'application',
             'description': 'OMA Download Agents'},
    '.cat': {'file_end': '.cat', 'type': 'application/vnd.ms-pki.seccat', 'name': 'application',
             'description': 'Microsoft Trust UI Provider - Security Catalog'},
    '.tcap': {'file_end': '.tcap', 'type': 'application/vnd.3gpp2.tcap', 'name': 'application',
              'description': '3rd Generation Partnership Project - Transaction Capabilities Application Part'},
    '.c4g': {'file_end': '.c4g', 'type': 'application/vnd.clonk.c4group', 'name': 'application',
             'description': 'Clonk Game'},
    '.texinfo': {'file_end': '.texinfo', 'type': 'application/x-texinfo', 'name': 'application',
                 'description': 'GNU Texinfo Document'},
    '.p8': {'file_end': '.p8', 'type': 'application/pkcs8', 'name': 'application',
            'description': 'PKCS #8 - Private-Key Information Syntax Standard'},
    '.vis': {'file_end': '.vis', 'type': 'application/vnd.visionary', 'name': 'application',
             'description': 'Visionary'},
    '.ddd': {'file_end': '.ddd', 'type': 'application/vnd.fujixerox.ddd', 'name': 'application',
             'description': 'Fujitsu - Xerox 2D CAD Data'},
    '.link66': {'file_end': '.link66', 'type': 'application/vnd.route66.link66+xml', 'name': 'application',
                'description': 'ROUTE 66 Location Based Services'},
    '.tmo': {'file_end': '.tmo', 'type': 'application/vnd.tmobile-livetv', 'name': 'application',
             'description': 'MobileTV'},
    '.ext': {'file_end': '.ext', 'type': 'application/vnd.novadigm.ext', 'name': 'application',
             'description': "Novadigm's RADIA and EDM products"},
    '.exi': {'file_end': '.exi', 'type': 'application/exi', 'name': 'application',
             'description': 'Efficient XML Interchange'},
    '.mus': {'file_end': '.mus', 'type': 'application/vnd.musician', 'name': 'application',
             'description': 'MUsical Score Interpreted Code Invented for the ASCII designation of Notation'},
    '.opf': {'file_end': '.opf', 'type': 'application/oebps-package+xml', 'name': 'application',
             'description': 'Open eBook Publication Structure'},
    '.exe': {'file_end': '.exe', 'type': 'application/x-msdownload', 'name': 'application',
             'description': 'Microsoft Application'},
    '.xpw': {'file_end': '.xpw', 'type': 'application/vnd.intercon.formnet', 'name': 'application',
             'description': 'Intercon FormNet'},
    '.xpr': {'file_end': '.xpr', 'type': 'application/vnd.is-xpr', 'name': 'application',
             'description': 'Express by Infoseek'},
    '.xps': {'file_end': '.xps', 'type': 'application/vnd.ms-xpsdocument', 'name': 'application',
             'description': 'Microsoft XML Paper Specification'},
    '.res': {'file_end': '.res', 'type': 'application/x-dtbresource+xml', 'name': 'application',
             'description': 'Digital Talking Book - Resource File'},
    '.rep': {'file_end': '.rep', 'type': 'application/vnd.businessobjects', 'name': 'application',
             'description': 'BusinessObjects'},
    '.torrent': {'file_end': '.torrent', 'type': 'application/x-bittorrent', 'name': 'application',
                 'description': 'BitTorrent'},
    '.xpi': {'file_end': '.xpi', 'type': 'application/x-xpinstall', 'name': 'application',
             'description': 'XPInstall - Mozilla'},
    '.m21': {'file_end': '.m21', 'type': 'application/mp21', 'name': 'application', 'description': 'MPEG-21'},
    '.spq': {'file_end': '.spq', 'type': 'application/scvp-vp-request', 'name': 'application',
             'description': 'Server-Based Certificate Validation Protocol - Validation Policies - Request'},
    '.spp': {'file_end': '.spp', 'type': 'application/scvp-vp-response', 'name': 'application',
             'description': 'Server-Based Certificate Validation Protocol - Validation Policies - Response'},
    '.ami': {'file_end': '.ami', 'type': 'application/vnd.amiga.ami', 'name': 'application', 'description': 'AmigaDE'},
    '.fm': {'file_end': '.fm', 'type': 'application/vnd.framemaker', 'name': 'application',
            'description': 'FrameMaker Normal Format'},
    '.dssc': {'file_end': '.dssc', 'type': 'application/dssc+der', 'name': 'application',
              'description': 'Data Structure for the Security Suitability of Cryptographic Algorithms'},
    '.spf': {'file_end': '.spf', 'type': 'application/vnd.yamaha.smaf-phrase', 'name': 'application',
             'description': 'SMAF Phrase'},
    '.spl': {'file_end': '.spl', 'type': 'application/x-futuresplash', 'name': 'application',
             'description': 'FutureSplash Animator'},
    '.mgp': {'file_end': '.mgp', 'type': 'application/vnd.osgeo.mapguide.package', 'name': 'application',
             'description': 'MapGuide DBXML'},
    '.emma': {'file_end': '.emma', 'type': 'application/emma+xml', 'name': 'application',
              'description': 'Extensible MultiModal Annotation'},
    '.mgz': {'file_end': '.mgz', 'type': 'application/vnd.proteus.magazine', 'name': 'application',
             'description': 'EFI Proteus'},
    'N/A': {'file_end': 'N/A', 'type': 'application/andrew-inset', 'name': 'application',
            'description': 'Andrew Toolkit'},
    '.gac': {'file_end': '.gac', 'type': 'application/vnd.groove-account', 'name': 'application',
             'description': 'Groove - Account'},
    '.cww': {'file_end': '.cww', 'type': 'application/prs.cww', 'name': 'application', 'description': 'CU-Writer'},
    '.efif': {'file_end': '.efif', 'type': 'application/vnd.picsel', 'name': 'application',
              'description': 'Pcsel eFIF File'},
    '.yin': {'file_end': '.yin', 'type': 'application/yin+xml', 'name': 'application',
             'description': 'YIN (YANG - XML)'},
    '.wad': {'file_end': '.wad', 'type': 'application/x-doom', 'name': 'application', 'description': 'Doom Video Game'},
    '.saf': {'file_end': '.saf', 'type': 'application/vnd.yamaha.smaf-audio', 'name': 'application',
             'description': 'SMAF Audio'},
    '.txf': {'file_end': '.txf', 'type': 'application/vnd.mobius.txf', 'name': 'application',
             'description': 'Mobius Management Systems - Topic Index File'},
    '.utz': {'file_end': '.utz', 'type': 'application/vnd.uiq.theme', 'name': 'application',
             'description': 'User Interface Quartz - Theme (Symbian)'},
    '.txd': {'file_end': '.txd', 'type': 'application/vnd.genomatix.tuxedo', 'name': 'application',
             'description': 'Genomatix Tuxedo Framework'},
    '.rsd': {'file_end': '.rsd', 'type': 'application/rsd+xml', 'name': 'application',
             'description': 'Really Simple Discovery'},
    '.xsm': {'file_end': '.xsm', 'type': 'application/vnd.syncml+xml', 'name': 'application', 'description': 'SyncML'},
    '.xbd': {'file_end': '.xbd', 'type': 'application/vnd.fujixerox.docuworks.binder', 'name': 'application',
             'description': 'Fujitsu - Xerox DocuWorks Binder'},
    '.mlp': {'file_end': '.mlp', 'type': 'application/vnd.dolby.mlp', 'name': 'application',
             'description': 'Dolby Meridian Lossless Packing'},
    '.twd': {'file_end': '.twd', 'type': 'application/vnd.simtech-mindmapper', 'name': 'application',
             'description': 'SimTech MindMapper'},
    '.dna': {'file_end': '.dna', 'type': 'application/vnd.dna', 'name': 'application',
             'description': 'New Moon Liftoff/DNA'},
    '.ahead': {'file_end': '.ahead', 'type': 'application/vnd.ahead.space', 'name': 'application',
               'description': 'Ahead AIR Application'},
    '.fnc': {'file_end': '.fnc', 'type': 'application/vnd.frogans.fnc', 'name': 'application',
             'description': 'Frogans Player'},
    '.daf': {'file_end': '.daf', 'type': 'application/vnd.mobius.daf', 'name': 'application',
             'description': 'Mobius Management Systems - UniversalArchive'},
    '.cer': {'file_end': '.cer', 'type': 'application/pkix-cert', 'name': 'application',
             'description': 'Internet Public Key Infrastructure - Certificate'},
    '.smf': {'file_end': '.smf', 'type': 'application/vnd.stardivision.math', 'name': 'application',
             'description': 'StarOffice - Math'},
    '.ttf': {'file_end': '.ttf', 'type': 'application/x-font-ttf', 'name': 'application',
             'description': 'TrueType Font'},
    '.dotm': {'file_end': '.dotm', 'type': 'application/vnd.ms-word.template.macroenabled.12', 'name': 'application',
              'description': 'Micosoft Word - Macro-Enabled Template'},
    '.smi': {'file_end': '.smi', 'type': 'application/smil+xml', 'name': 'application',
             'description': 'Synchronized Multimedia Integration Language'},
    '.gxt': {'file_end': '.gxt', 'type': 'application/vnd.geonext', 'name': 'application',
             'description': 'GEONExT and JSXGraph'},
    '.jisp': {'file_end': '.jisp', 'type': 'application/vnd.jisp', 'name': 'application', 'description': 'RhymBox'},
    '.sfs': {'file_end': '.sfs', 'type': 'application/vnd.spotfire.sfs', 'name': 'application',
             'description': 'TIBCO Spotfire'},
    '.dxp': {'file_end': '.dxp', 'type': 'application/vnd.spotfire.dxp', 'name': 'application',
             'description': 'TIBCO Spotfire'},
    '.kia': {'file_end': '.kia', 'type': 'application/vnd.kidspiration', 'name': 'application',
             'description': 'Kidspiration'},
    '.tar': {'file_end': '.tar', 'type': 'application/x-tar', 'name': 'application',
             'description': 'Tar File (Tape Archive)'},
    '.mqy': {'file_end': '.mqy', 'type': 'application/vnd.mobius.mqy', 'name': 'application',
             'description': 'Mobius Management Systems - Query File'},
    '.rnc': {'file_end': '.rnc', 'type': 'application/relax-ng-compact-syntax', 'name': 'application',
             'description': 'Relax NG Compact Syntax'},
    '.tao': {'file_end': '.tao', 'type': 'application/vnd.tao.intent-module-archive', 'name': 'application',
             'description': 'Tao Intent'},
    '.xlsx': {'file_end': '.xlsx', 'type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Spreadsheet'},
    '.wgt': {'file_end': '.wgt', 'type': 'application/widget', 'name': 'application',
             'description': 'Widget Packaging and XML Configuration'},
    '.hpgl': {'file_end': '.hpgl', 'type': 'application/vnd.hp-hpgl', 'name': 'application',
              'description': 'HP-GL/2 and HP RTL'},
    '.dotx': {'file_end': '.dotx', 'type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Word Document Template'},
    '.cu': {'file_end': '.cu', 'type': 'application/cu-seeme', 'name': 'application', 'description': 'CU-SeeMe'},
    '.chrt': {'file_end': '.chrt', 'type': 'application/vnd.kde.kchart', 'name': 'application',
              'description': 'KDE KOffice Office Suite - KChart'},
    '.wsdl': {'file_end': '.wsdl', 'type': 'application/wsdl+xml', 'name': 'application',
              'description': 'WSDL - Web Services Description Language'},
    '.fg5': {'file_end': '.fg5', 'type': 'application/vnd.fujitsu.oasysgp', 'name': 'application',
             'description': 'Fujitsu Oasys'},
    '.ei6': {'file_end': '.ei6', 'type': 'application/vnd.pg.osasli', 'name': 'application',
             'description': 'Proprietary P&G Standard Reporting System'},
    '.svc': {'file_end': '.svc', 'type': 'application/vnd.dvb.service', 'name': 'application',
             'description': 'Digital Video Broadcasting'},
    '.mcd': {'file_end': '.mcd', 'type': 'application/vnd.mcd', 'name': 'application',
             'description': 'Micro CADAM Helix D&D'},
    '.odft': {'file_end': '.odft', 'type': 'application/vnd.oasis.opendocument.formula-template', 'name': 'application',
              'description': 'OpenDocument Formula Template'},
    '.nnd': {'file_end': '.nnd', 'type': 'application/vnd.noblenet-directory', 'name': 'application',
             'description': 'NobleNet Directory'},
    '.pgn': {'file_end': '.pgn', 'type': 'application/x-chess-pgn', 'name': 'application',
             'description': 'Portable Game Notation (Chess Games)'},
    '.str': {'file_end': '.str', 'type': 'application/vnd.pg.format', 'name': 'application',
             'description': 'Proprietary P&G Standard Reporting System'},
    '.g2w': {'file_end': '.g2w', 'type': 'application/vnd.geoplan', 'name': 'application', 'description': 'GeoplanW'},
    '.stw': {'file_end': '.stw', 'type': 'application/vnd.sun.xml.writer.template', 'name': 'application',
             'description': 'OpenOffice - Writer Template (Text - HTML)'},
    '.sti': {'file_end': '.sti', 'type': 'application/vnd.sun.xml.impress.template', 'name': 'application',
             'description': 'OpenOffice - Impress Template (Presentation)'},
    '.nns': {'file_end': '.nns', 'type': 'application/vnd.noblenet-sealer', 'name': 'application',
             'description': 'NobleNet Sealer'},
    '.stk': {'file_end': '.stk', 'type': 'application/hyperstudio', 'name': 'application',
             'description': 'Hyperstudio'},
    '.crl': {'file_end': '.crl', 'type': 'application/pkix-crl', 'name': 'application',
             'description': 'Internet Public Key Infrastructure - Certificate Revocation Lists'},
    '.ipfix': {'file_end': '.ipfix', 'type': 'application/ipfix', 'name': 'application',
               'description': 'Internet Protocol Flow Information Export'},
    '.nnw': {'file_end': '.nnw', 'type': 'application/vnd.noblenet-web', 'name': 'application',
             'description': 'NobleNet Web'},
    '.osf': {'file_end': '.osf', 'type': 'application/vnd.yamaha.openscoreformat', 'name': 'application',
             'description': 'Open Score Format'},
    '.bed': {'file_end': '.bed', 'type': 'application/vnd.realvnc.bed', 'name': 'application',
             'description': 'RealVNC'},
    '.stc': {'file_end': '.stc', 'type': 'application/vnd.sun.xml.calc.template', 'name': 'application',
             'description': 'OpenOffice - Calc Template (Spreadsheet)'},
    '.crd': {'file_end': '.crd', 'type': 'application/x-mscardfile', 'name': 'application',
             'description': 'Microsoft Information Card'},
    '.std': {'file_end': '.std', 'type': 'application/vnd.sun.xml.draw.template', 'name': 'application',
             'description': 'OpenOffice - Draw Template (Graphics)'},
    '.stf': {'file_end': '.stf', 'type': 'application/vnd.wt.stf', 'name': 'application', 'description': 'Worldtalk'},
    '.gmx': {'file_end': '.gmx', 'type': 'application/vnd.gmx', 'name': 'application',
             'description': 'GameMaker ActiveX'},
    '.qfx': {'file_end': '.qfx', 'type': 'application/vnd.intu.qfx', 'name': 'application', 'description': 'Quicken'},
    '.mrcx': {'file_end': '.mrcx', 'type': 'application/marcxml+xml', 'name': 'application',
              'description': 'MARC21 XML Schema'},
    '.cla': {'file_end': '.cla', 'type': 'application/vnd.claymore', 'name': 'application',
             'description': 'Claymore Data Files'},
    '.pwn': {'file_end': '.pwn', 'type': 'application/vnd.3m.post-it-notes', 'name': 'application',
             'description': '3M Post It Notes'},
    '.lwp': {'file_end': '.lwp', 'type': 'application/vnd.lotus-wordpro', 'name': 'application',
             'description': 'Lotus Wordpro'},
    '.pskcxml': {'file_end': '.pskcxml', 'type': 'application/pskc+xml', 'name': 'application',
                 'description': 'Portable Symmetric Key Container'},
    '.wmf': {'file_end': '.wmf', 'type': 'application/x-msmetafile', 'name': 'application',
             'description': 'Microsoft Windows Metafile'},
    '.wmd': {'file_end': '.wmd', 'type': 'application/x-ms-wmd', 'name': 'application',
             'description': 'Microsoft Windows Media Player Download Package'},
    '.wmz': {'file_end': '.wmz', 'type': 'application/x-ms-wmz', 'name': 'application',
             'description': 'Microsoft Windows Media Player Skin Package'},
    '.clp': {'file_end': '.clp', 'type': 'application/x-msclip', 'name': 'application',
             'description': 'Microsoft Clipboard Clip'},
    '.hps': {'file_end': '.hps', 'type': 'application/vnd.hp-hps', 'name': 'application',
             'description': "Hewlett-Packard's WebPrintSmart"},
    '.mc1': {'file_end': '.mc1', 'type': 'application/vnd.medcalcdata', 'name': 'application',
             'description': 'MedCalc'},
    '.p12': {'file_end': '.p12', 'type': 'application/x-pkcs12', 'name': 'application',
             'description': 'PKCS #12 - Personal Information Exchange Syntax Standard'},
    '.kpr': {'file_end': '.kpr', 'type': 'application/vnd.kde.kpresenter', 'name': 'application',
             'description': 'KDE KOffice Office Suite - Kpresenter'},
    '.oa2': {'file_end': '.oa2', 'type': 'application/vnd.fujitsu.oasys2', 'name': 'application',
             'description': 'Fujitsu Oasys'},
    '.oa3': {'file_end': '.oa3', 'type': 'application/vnd.fujitsu.oasys3', 'name': 'application',
             'description': 'Fujitsu Oasys'},
    '.gtar': {'file_end': '.gtar', 'type': 'application/x-gtar', 'name': 'application', 'description': 'GNU Tar Files'},
    '.p7m': {'file_end': '.p7m', 'type': 'application/pkcs7-mime', 'name': 'application',
             'description': 'PKCS #7 - Cryptographic Message Syntax Standard'},
    '.deb': {'file_end': '.deb', 'type': 'application/x-debian-package', 'name': 'application',
             'description': 'Debian Package'},
    '.p7b': {'file_end': '.p7b', 'type': 'application/x-pkcs7-certificates', 'name': 'application',
             'description': 'PKCS #7 - Cryptographic Message Syntax Standard (Certificates)'},
    '.der': {'file_end': '.der', 'type': 'application/x-x509-ca-cert', 'name': 'application',
             'description': 'X.509 Certificate'},
    '.p7s': {'file_end': '.p7s', 'type': 'application/pkcs7-signature', 'name': 'application',
             'description': 'PKCS #7 - Cryptographic Message Syntax Standard'},
    '.p7r': {'file_end': '.p7r', 'type': 'application/x-pkcs7-certreqresp', 'name': 'application',
             'description': 'PKCS #7 - Cryptographic Message Syntax Standard (Certificate Request Response)'},
    '.fxp': {'file_end': '.fxp', 'type': 'application/vnd.adobe.fxp', 'name': 'application',
             'description': 'Adobe Flex Project'},
    '.acc': {'file_end': '.acc', 'type': 'application/vnd.americandynamics.acc', 'name': 'application',
             'description': 'Active Content Compression'},
    '.otc': {'file_end': '.otc', 'type': 'application/vnd.oasis.opendocument.chart-template', 'name': 'application',
             'description': 'OpenDocument Chart Template'},
    '.c11amz': {'file_end': '.c11amz', 'type': 'application/vnd.cluetrust.cartomobile-config-pkg',
                'name': 'application', 'description': 'ClueTrust CartoMobile - Config Package'},
    '.ace': {'file_end': '.ace', 'type': 'application/x-ace-compressed', 'name': 'application',
             'description': 'Ace Archive'},
    '.acu': {'file_end': '.acu', 'type': 'application/vnd.acucobol', 'name': 'application', 'description': 'ACU Cobol'},
    '.wmlsc': {'file_end': '.wmlsc', 'type': 'application/vnd.wap.wmlscriptc', 'name': 'application',
               'description': 'WMLScript'},
    '.oas': {'file_end': '.oas', 'type': 'application/vnd.fujitsu.oasys', 'name': 'application',
             'description': 'Fujitsu Oasys'},
    '.c11amc': {'file_end': '.c11amc', 'type': 'application/vnd.cluetrust.cartomobile-config', 'name': 'application',
                'description': 'ClueTrust CartoMobile - Config'},
    '.tex': {'file_end': '.tex', 'type': 'application/x-tex', 'name': 'application', 'description': 'TeX'},
    '.wri': {'file_end': '.wri', 'type': 'application/x-mswrite', 'name': 'application',
             'description': 'Microsoft Wordpad'},
    '.irp': {'file_end': '.irp', 'type': 'application/vnd.irepository.package+xml', 'name': 'application',
             'description': 'iRepository / Lucidoc Editor'},
    '.sse': {'file_end': '.sse', 'type': 'application/vnd.kodak-descriptor', 'name': 'application',
             'description': 'Kodak Storyshare'},
    '.ssf': {'file_end': '.ssf', 'type': 'application/vnd.epson.ssf', 'name': 'application',
             'description': 'QUASS Stream Player'},
    '.sitx': {'file_end': '.sitx', 'type': 'application/x-stuffitx', 'name': 'application',
              'description': 'Stuffit Archive'},
    '.hal': {'file_end': '.hal', 'type': 'application/vnd.hal+xml', 'name': 'application',
             'description': 'Hypertext Application Language'},
    '.tei': {'file_end': '.tei', 'type': 'application/tei+xml', 'name': 'application',
             'description': 'Text Encoding and Interchange'},
    '.meta4': {'file_end': '.meta4', 'type': 'application/metalink4+xml', 'name': 'application',
               'description': 'Metalink'},
    '.irm': {'file_end': '.irm', 'type': 'application/vnd.ibm.rights-management', 'name': 'application',
             'description': 'IBM DB2 Rights Manager'},
    '.joda': {'file_end': '.joda', 'type': 'application/vnd.joost.joda-archive', 'name': 'application',
              'description': 'Joda Archive'},
    '.rpst': {'file_end': '.rpst', 'type': 'application/vnd.nokia.radio-preset', 'name': 'application',
              'description': 'Nokia Radio Application - Preset'},
    '.fdf': {'file_end': '.fdf', 'type': 'application/vnd.fdf', 'name': 'application',
             'description': 'Forms Data Format'},
    '.rpss': {'file_end': '.rpss', 'type': 'application/vnd.nokia.radio-presets', 'name': 'application',
              'description': 'Nokia Radio Application - Preset'},
    '.mfm': {'file_end': '.mfm', 'type': 'application/vnd.mfmp', 'name': 'application',
             'description': 'Melody Format for Mobile Platform'},
    '.paw': {'file_end': '.paw', 'type': 'application/vnd.pawaafile', 'name': 'application',
             'description': 'PawaaFILE'},
    '.gim': {'file_end': '.gim', 'type': 'application/vnd.groove-identity-message', 'name': 'application',
             'description': 'Groove - Identity Message'},
    '.kfo': {'file_end': '.kfo', 'type': 'application/vnd.kde.kformula', 'name': 'application',
             'description': 'KDE KOffice Office Suite - Kformula'},
    '.lrm': {'file_end': '.lrm', 'type': 'application/vnd.ms-lrm', 'name': 'application',
             'description': 'Microsoft Learning Resource Module'},
    '.cdkey': {'file_end': '.cdkey', 'type': 'application/vnd.mediastation.cdkey', 'name': 'application',
               'description': 'MediaRemote'},
    '.atomcat': {'file_end': '.atomcat', 'type': 'application/atomcat+xml', 'name': 'application',
                 'description': 'Atom Publishing Protocol'},
    '.i2g': {'file_end': '.i2g', 'type': 'application/vnd.intergeo', 'name': 'application',
             'description': 'Interactive Geometry Software'},
    '.rtf': {'file_end': '.rtf', 'type': 'application/rtf', 'name': 'application', 'description': 'Rich Text Format'},
    '.xhtml': {'file_end': '.xhtml', 'type': 'application/xhtml+xml', 'name': 'application',
               'description': 'XHTML - The Extensible HyperText Markup Language'},
    '.fcs': {'file_end': '.fcs', 'type': 'application/vnd.isac.fcs', 'name': 'application',
             'description': 'International Society for Advancement of Cytometry'},
    '.azs': {'file_end': '.azs', 'type': 'application/vnd.airzip.filesecure.azs', 'name': 'application',
             'description': 'AirZip FileSECURE'},
    '.kon': {'file_end': '.kon', 'type': 'application/vnd.kde.kontour', 'name': 'application',
             'description': 'KDE KOffice Office Suite - Kontour'},
    '.ngdat': {'file_end': '.ngdat', 'type': 'application/vnd.nokia.n-gage.data', 'name': 'application',
               'description': 'N-Gage Game Data'},
    '.azf': {'file_end': '.azf', 'type': 'application/vnd.airzip.filesecure.azf', 'name': 'application',
             'description': 'AirZip FileSECURE'},
    '.wbxml': {'file_end': '.wbxml', 'type': 'application/vnd.wap.wbxml', 'name': 'application',
               'description': 'WAP Binary XML (WBXML)'},
    '.mathml': {'file_end': '.mathml', 'type': 'application/mathml+xml', 'name': 'application',
                'description': 'Mathematical Markup Language'},
    '.vcd': {'file_end': '.vcd', 'type': 'application/x-cdlink', 'name': 'application', 'description': 'Video CD'},
    '.vcg': {'file_end': '.vcg', 'type': 'application/vnd.groove-vcard', 'name': 'application',
             'description': 'Groove - Vcard'},
    '.json': {'file_end': '.json', 'type': 'application/json', 'name': 'application',
              'description': 'JavaScript Object Notation (JSON)'},
    '.shf': {'file_end': '.shf', 'type': 'application/shf+xml', 'name': 'application',
             'description': 'S Hexdump Format'},
    '.grv': {'file_end': '.grv', 'type': 'application/vnd.groove-injector', 'name': 'application',
             'description': 'Groove - Injector'},
    '.tpt': {'file_end': '.tpt', 'type': 'application/vnd.trid.tpt', 'name': 'application',
             'description': 'TRI Systems Config'},
    '.psb': {'file_end': '.psb', 'type': 'application/vnd.3gpp.pic-bw-small', 'name': 'application',
             'description': '3rd Generation Partnership Project - Pic Small'},
    '.vxml': {'file_end': '.vxml', 'type': 'application/voicexml+xml', 'name': 'application',
              'description': 'VoiceXML'},
    '.psf': {'file_end': '.psf', 'type': 'application/x-font-linux-psf', 'name': 'application',
             'description': 'PSF Fonts'},
    '.tpl': {'file_end': '.tpl', 'type': 'application/vnd.groove-tool-template', 'name': 'application',
             'description': 'Groove - Tool Template'},
    '.htke': {'file_end': '.htke', 'type': 'application/vnd.kenameaapp', 'name': 'application',
              'description': 'Kenamea App'},
    '.vcx': {'file_end': '.vcx', 'type': 'application/vnd.vcx', 'name': 'application', 'description': 'VirtualCatalog'},
    '.odg': {'file_end': '.odg', 'type': 'application/vnd.oasis.opendocument.graphics', 'name': 'application',
             'description': 'OpenDocument Graphics'},
    '.odf': {'file_end': '.odf', 'type': 'application/vnd.oasis.opendocument.formula', 'name': 'application',
             'description': 'OpenDocument Formula'},
    '.oda': {'file_end': '.oda', 'type': 'application/oda', 'name': 'application',
             'description': 'Office Document Architecture'},
    '.ustar': {'file_end': '.ustar', 'type': 'application/x-ustar', 'name': 'application',
               'description': 'Ustar (Uniform Standard Tape Archive)'},
    '.odc': {'file_end': '.odc', 'type': 'application/vnd.oasis.opendocument.chart', 'name': 'application',
             'description': 'OpenDocument Chart'},
    '.odb': {'file_end': '.odb', 'type': 'application/vnd.oasis.opendocument.database', 'name': 'application',
             'description': 'OpenDocument Database'},
    '.m3u8': {'file_end': '.m3u8', 'type': 'application/vnd.apple.mpegurl', 'name': 'application',
              'description': 'Multimedia Playlist Unicode'},
    '.cdmid': {'file_end': '.cdmid', 'type': 'application/cdmi-domain', 'name': 'application',
               'description': 'Cloud Data Management Interface (CDMI) - Domain'},
    '.see': {'file_end': '.see', 'type': 'application/vnd.seemail', 'name': 'application', 'description': 'SeeMail'},
    '.odi': {'file_end': '.odi', 'type': 'application/vnd.oasis.opendocument.image', 'name': 'application',
             'description': 'OpenDocument Image'},
    '.azw': {'file_end': '.azw', 'type': 'application/vnd.amazon.ebook', 'name': 'application',
             'description': 'Amazon Kindle eBook format'},
    '.mpkg': {'file_end': '.mpkg', 'type': 'application/vnd.apple.installer+xml', 'name': 'application',
              'description': 'Apple Installer Package'},
    '.odt': {'file_end': '.odt', 'type': 'application/vnd.oasis.opendocument.text', 'name': 'application',
             'description': 'OpenDocument Text'},
    '.odp': {'file_end': '.odp', 'type': 'application/vnd.oasis.opendocument.presentation', 'name': 'application',
             'description': 'OpenDocument Presentation'},
    '.ods': {'file_end': '.ods', 'type': 'application/vnd.oasis.opendocument.spreadsheet', 'name': 'application',
             'description': 'OpenDocument Spreadsheet'},
    '.cdmiq': {'file_end': '.cdmiq', 'type': 'application/cdmi-queue', 'name': 'application',
               'description': 'Cloud Data Management Interface (CDMI) - Queue'},
    '.mpn': {'file_end': '.mpn', 'type': 'application/vnd.mophun.application', 'name': 'application',
             'description': 'Mophun VM'},
    '.mpm': {'file_end': '.mpm', 'type': 'application/vnd.blueice.multipass', 'name': 'application',
             'description': 'Blueice Research Multipass'},
    '.mpc': {'file_end': '.mpc', 'type': 'application/vnd.mophun.certificate', 'name': 'application',
             'description': 'Mophun Certificate'},
    '.xdssc': {'file_end': '.xdssc', 'type': 'application/dssc+xml', 'name': 'application',
               'description': 'Data Structure for the Security Suitability of Cryptographic Algorithms'},
    '.mpy': {'file_end': '.mpy', 'type': 'application/vnd.ibm.minipay', 'name': 'application',
             'description': 'MiniPay'},
    '.wpd': {'file_end': '.wpd', 'type': 'application/vnd.wordperfect', 'name': 'application',
             'description': 'Wordperfect'},
    '.tfi': {'file_end': '.tfi', 'type': 'application/thraud+xml', 'name': 'application',
             'description': 'Sharing Transaction Fraud Data'},
    '.mpp': {'file_end': '.mpp', 'type': 'application/vnd.ms-project', 'name': 'application',
             'description': 'Microsoft Project'},
    '.tfm': {'file_end': '.tfm', 'type': 'application/x-tex-tfm', 'name': 'application',
             'description': 'TeX Font Metric'},
    '.xspf': {'file_end': '.xspf', 'type': 'application/xspf+xml', 'name': 'application',
              'description': 'XSPF - XML Shareable Playlist Format'},
    '.nsf': {'file_end': '.nsf', 'type': 'application/vnd.lotus-notes', 'name': 'application',
             'description': 'Lotus Notes'},
    '.wmlc': {'file_end': '.wmlc', 'type': 'application/vnd.wap.wmlc', 'name': 'application',
              'description': 'Compiled Wireless Markup Language (WMLC)'},
    '.ppsx': {'file_end': '.ppsx', 'type': 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Presentation (Slideshow)'},
    '.hlp': {'file_end': '.hlp', 'type': 'application/winhlp', 'name': 'application', 'description': 'WinHelp'},
    '.dpg': {'file_end': '.dpg', 'type': 'application/vnd.dpgraph', 'name': 'application', 'description': 'DPGraph'},
    '.ggt': {'file_end': '.ggt', 'type': 'application/vnd.geogebra.tool', 'name': 'application',
             'description': 'GeoGebra'},
    '.ppsm': {'file_end': '.ppsm', 'type': 'application/vnd.ms-powerpoint.slideshow.macroenabled.12',
              'name': 'application', 'description': 'Microsoft PowerPoint - Macro-Enabled Slide Show File'},
    '.sv4cpio': {'file_end': '.sv4cpio', 'type': 'application/x-sv4cpio', 'name': 'application',
                 'description': 'System V Release 4 CPIO Archive'},
    '.karbon': {'file_end': '.karbon', 'type': 'application/vnd.kde.karbon', 'name': 'application',
                'description': 'KDE KOffice Office Suite - Karbon'},
    '.jnlp': {'file_end': '.jnlp', 'type': 'application/x-java-jnlp-file', 'name': 'application',
              'description': 'Java Network Launching Protocol'},
    '.ivp': {'file_end': '.ivp', 'type': 'application/vnd.immervision-ivp', 'name': 'application',
             'description': 'ImmerVision PURE Players'},
    '.ivu': {'file_end': '.ivu', 'type': 'application/vnd.immervision-ivu', 'name': 'application',
             'description': 'ImmerVision PURE Players'},
    '.sldx': {'file_end': '.sldx', 'type': 'application/vnd.openxmlformats-officedocument.presentationml.slide',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Presentation (Slide)'},
    '.yang': {'file_end': '.yang', 'type': 'application/yang', 'name': 'application',
              'description': 'YANG Data Modeling Language'},
    '.swf': {'file_end': '.swf', 'type': 'application/x-shockwave-flash', 'name': 'application',
             'description': 'Adobe Flash'},
    '.swi': {'file_end': '.swi', 'type': 'application/vnd.aristanetworks.swi', 'name': 'application',
             'description': 'Arista Networks Software Image'},
    '.sldm': {'file_end': '.sldm', 'type': 'application/vnd.ms-powerpoint.slide.macroenabled.12', 'name': 'application',
              'description': 'Microsoft PowerPoint - Macro-Enabled Open XML Slide'},
    '.pfa': {'file_end': '.pfa', 'type': 'application/x-font-type1', 'name': 'application',
             'description': 'PostScript Fonts'},
    '.mp4': {'file_end': '.mp4', 'type': 'application/mp4', 'name': 'application', 'description': 'MPEG4'},
    '.hvp': {'file_end': '.hvp', 'type': 'application/vnd.yamaha.hv-voice', 'name': 'application',
             'description': 'HV Voice Parameter'},
    '.rm': {'file_end': '.rm', 'type': 'application/vnd.rn-realmedia', 'name': 'application',
            'description': 'RealMedia'},
    '.hvs': {'file_end': '.hvs', 'type': 'application/vnd.yamaha.hv-script', 'name': 'application',
             'description': 'HV Script'},
    '.src': {'file_end': '.src', 'type': 'application/x-wais-source', 'name': 'application',
             'description': 'WAIS Source'},
    '.sbml': {'file_end': '.sbml', 'type': 'application/sbml+xml', 'name': 'application',
              'description': 'Systems Biology Markup Language'},
    '.seed': {'file_end': '.seed', 'type': 'application/vnd.fdsn.seed', 'name': 'application',
              'description': 'Digital Siesmograph Networks - SEED Datafiles'},
    '.hvd': {'file_end': '.hvd', 'type': 'application/vnd.yamaha.hv-dic', 'name': 'application',
             'description': 'HV Voice Dictionary'},
    '.sxd': {'file_end': '.sxd', 'type': 'application/vnd.sun.xml.draw', 'name': 'application',
             'description': 'OpenOffice - Draw (Graphics)'},
    '.rs': {'file_end': '.rs', 'type': 'application/rls-services+xml', 'name': 'application',
            'description': 'XML Resource Lists'},
    '.ppam': {'file_end': '.ppam', 'type': 'application/vnd.ms-powerpoint.addin.macroenabled.12', 'name': 'application',
              'description': 'Microsoft PowerPoint - Add-in file'},
    '.rq': {'file_end': '.rq', 'type': 'application/sparql-query', 'name': 'application',
            'description': 'SPARQL - Query'},
    '.rdz': {'file_end': '.rdz', 'type': 'application/vnd.data-vision.rdz', 'name': 'application',
             'description': 'RemoteDocs R-Viewer'},
    '.xop': {'file_end': '.xop', 'type': 'application/xop+xml', 'name': 'application',
             'description': 'XML-Binary Optimized Packaging'},
    '.xdf': {'file_end': '.xdf', 'type': 'application/xcap-diff+xml', 'name': 'application',
             'description': 'XML Configuration Access Protocol - XCAP Diff'},
    '.cod': {'file_end': '.cod', 'type': 'application/vnd.rim.cod', 'name': 'application',
             'description': 'Blackberry COD File'},
    '.osfpvg': {'file_end': '.osfpvg', 'type': 'application/vnd.yamaha.openscoreformat.osfpvg+xml',
                'name': 'application', 'description': 'OSFPVG'},
    '.skp': {'file_end': '.skp', 'type': 'application/vnd.koan', 'name': 'application',
             'description': 'SSEYO Koan Play File'},
    '.hqx': {'file_end': '.hqx', 'type': 'application/mac-binhex40', 'name': 'application',
             'description': 'Macintosh BinHex 4.0'},
    '.ksp': {'file_end': '.ksp', 'type': 'application/vnd.kde.kspread', 'name': 'application',
             'description': 'KDE KOffice Office Suite - Kspread'},
    '.sit': {'file_end': '.sit', 'type': 'application/x-stuffit', 'name': 'application',
             'description': 'Stuffit Archive'},
    '.doc': {'file_end': '.doc', 'type': 'application/msword', 'name': 'application', 'description': 'Microsoft Word'},
    '.wps': {'file_end': '.wps', 'type': 'application/vnd.ms-works', 'name': 'application',
             'description': 'Microsoft Works'},
    '.shar': {'file_end': '.shar', 'type': 'application/x-shar', 'name': 'application', 'description': 'Shell Archive'},
    '.ptid': {'file_end': '.ptid', 'type': 'application/vnd.pvi.ptid1', 'name': 'application',
              'description': 'Princeton Video Image'},
    '.ccxml': {'file_end': '.ccxml', 'type': 'application/ccxml+xml,', 'name': 'application',
               'description': 'Voice Browser Call Control'},
    '.cdy': {'file_end': '.cdy', 'type': 'application/vnd.cinderella', 'name': 'application',
             'description': 'Interactive Geometry Software Cinderella'},
    '.slt': {'file_end': '.slt', 'type': 'application/vnd.epson.salt', 'name': 'application',
             'description': 'SimpleAnimeLite Player'},
    '.qps': {'file_end': '.qps', 'type': 'application/vnd.publishare-delta-tree', 'name': 'application',
             'description': 'PubliShare Objects'},
    '.gsf': {'file_end': '.gsf', 'type': 'application/x-font-ghostscript', 'name': 'application',
             'description': 'Ghostscript Font'},
    '.uoml': {'file_end': '.uoml', 'type': 'application/vnd.uoml+xml', 'name': 'application',
              'description': 'Unique Object Markup Language'},
    '.icc': {'file_end': '.icc', 'type': 'application/vnd.iccprofile', 'name': 'application',
             'description': 'ICC profile'},
    '.ktz': {'file_end': '.ktz', 'type': 'application/vnd.kahootz', 'name': 'application', 'description': 'Kahootz'},
    '.cdbcmsg': {'file_end': '.cdbcmsg', 'type': 'application/vnd.contact.cmsg', 'name': 'application',
                 'description': 'CIM Database'},
    '.esf': {'file_end': '.esf', 'type': 'application/vnd.epson.esf', 'name': 'application',
             'description': 'QUASS Stream Player'},
    '.abw': {'file_end': '.abw', 'type': 'application/x-abiword', 'name': 'application', 'description': 'AbiWord'},
    '.wspolicy': {'file_end': '.wspolicy', 'type': 'application/wspolicy+xml', 'name': 'application',
                  'description': 'Web Services Policy'},
    '.epub': {'file_end': '.epub', 'type': 'application/epub+zip', 'name': 'application',
              'description': 'Electronic Publication'},
    '.pki': {'file_end': '.pki', 'type': 'application/pkixcmp', 'name': 'application',
             'description': 'Internet Public Key Infrastructure - Certificate Management Protocole'},
    '.hdf': {'file_end': '.hdf', 'type': 'application/x-hdf', 'name': 'application',
             'description': 'Hierarchical Data Format'},
    '.davmount': {'file_end': '.davmount', 'type': 'application/davmount+xml', 'name': 'application',
                  'description': 'Web Distributed Authoring and Versioning'},
    '.thmx': {'file_end': '.thmx', 'type': 'application/vnd.ms-officetheme', 'name': 'application',
              'description': 'Microsoft Office System Release Theme'},
    '.zaz': {'file_end': '.zaz', 'type': 'application/vnd.zzazz.deck+xml', 'name': 'application',
             'description': 'Zzazz Deck'},
    '.bdm': {'file_end': '.bdm', 'type': 'application/vnd.syncml.dm+wbxml', 'name': 'application',
             'description': 'SyncML - Device Management'},
    '.wqd': {'file_end': '.wqd', 'type': 'application/vnd.wqd', 'name': 'application', 'description': 'SundaHus WQ'},
    '.srx': {'file_end': '.srx', 'type': 'application/sparql-results+xml', 'name': 'application',
             'description': 'SPARQL - Results'},
    '.box': {'file_end': '.box', 'type': 'application/vnd.previewsystems.box', 'name': 'application',
             'description': 'Preview Systems ZipLock/VBox'},
    '.sru': {'file_end': '.sru', 'type': 'application/sru+xml', 'name': 'application',
             'description': 'Search/Retrieve via URL Response Format'},
    '.aw': {'file_end': '.aw', 'type': 'application/applixware', 'name': 'application', 'description': 'Applixware'},
    '.pbd': {'file_end': '.pbd', 'type': 'application/vnd.powerbuilder6', 'name': 'application',
             'description': 'PowerBuilder'},
    '.bh2': {'file_end': '.bh2', 'type': 'application/vnd.fujitsu.oasysprs', 'name': 'application',
             'description': 'Fujitsu Oasys'},
    '.mxml': {'file_end': '.mxml', 'type': 'application/xv+xml', 'name': 'application', 'description': 'MXML'},
    '.es3': {'file_end': '.es3', 'type': 'application/vnd.eszigno3+xml', 'name': 'application',
             'description': 'MICROSEC e-Szign\xc2\xa2'},
    '.qbo': {'file_end': '.qbo', 'type': 'application/vnd.intu.qbo', 'name': 'application',
             'description': 'Open Financial Exchange'},
    '.msty': {'file_end': '.msty', 'type': 'application/vnd.muvee.style', 'name': 'application',
              'description': 'Muvee Automatic Video Editing'},
    '.dtd': {'file_end': '.dtd', 'type': 'application/xml-dtd', 'name': 'application',
             'description': 'Document Type Definition'},
    '.dtb': {'file_end': '.dtb', 'type': 'application/x-dtbook+xml', 'name': 'application',
             'description': 'Digital Talking Book'},
    '.pclxl': {'file_end': '.pclxl', 'type': 'application/vnd.hp-pclxl', 'name': 'application',
               'description': 'PCL 6 Enhanced (Formely PCL XL)'},
    '.xdp': {'file_end': '.xdp', 'type': 'application/vnd.adobe.xdp+xml', 'name': 'application',
             'description': 'Adobe XML Data Package'},
    '.xdw': {'file_end': '.xdw', 'type': 'application/vnd.fujixerox.docuworks', 'name': 'application',
             'description': 'Fujitsu - Xerox DocuWorks'},
    '.mbk': {'file_end': '.mbk', 'type': 'application/vnd.mobius.mbk', 'name': 'application',
             'description': 'Mobius Management Systems - Basket file'},
    '.cdxml': {'file_end': '.cdxml', 'type': 'application/vnd.chemdraw+xml', 'name': 'application',
               'description': 'CambridgeSoft Chem Draw'},
    '.ipk': {'file_end': '.ipk', 'type': 'application/vnd.shana.informed.package', 'name': 'application',
             'description': 'Shana Informed Filler'},
    '.org': {'file_end': '.org', 'type': 'application/vnd.lotus-organizer', 'name': 'application',
             'description': 'Lotus Organizer'},
    '.xslt': {'file_end': '.xslt', 'type': 'application/xslt+xml', 'name': 'application',
              'description': 'XML Transformations'},
    '.apk': {'file_end': '.apk', 'type': 'application/vnd.android.package-archive', 'name': 'application',
             'description': 'Android Package Archive'},
    '.xdm': {'file_end': '.xdm', 'type': 'application/vnd.syncml.dm+xml', 'name': 'application',
             'description': 'SyncML - Device Management'},
    '.gqf': {'file_end': '.gqf', 'type': 'application/vnd.grafeq', 'name': 'application', 'description': 'GrafEq'},
    '.kne': {'file_end': '.kne', 'type': 'application/vnd.kinar', 'name': 'application',
             'description': 'Kinar Applications'},
    '.edx': {'file_end': '.edx', 'type': 'application/vnd.novadigm.edx', 'name': 'application',
             'description': "Novadigm's RADIA and EDM products"},
    '.flw': {'file_end': '.flw', 'type': 'application/vnd.kde.kivio', 'name': 'application',
             'description': 'KDE KOffice Office Suite - Kivio'},
    '.cdmio': {'file_end': '.cdmio', 'type': 'application/cdmi-object', 'name': 'application',
               'description': 'Cloud Data Management Interface (CDMI) - Object'},
    '.edm': {'file_end': '.edm', 'type': 'application/vnd.novadigm.edm', 'name': 'application',
             'description': "Novadigm's RADIA and EDM products"},
    '.ez2': {'file_end': '.ez2', 'type': 'application/vnd.ezpix-album', 'name': 'application',
             'description': 'EZPix Secure Photo Album'},
    '.nbp': {'file_end': '.nbp', 'type': 'application/vnd.wolfram.player', 'name': 'application',
             'description': 'Mathematica Notebook Player'},
    '.hbci': {'file_end': '.hbci', 'type': 'application/vnd.hbci', 'name': 'application',
              'description': 'Homebanking Computer Interface (HBCI)'},
    '.pkipath': {'file_end': '.pkipath', 'type': 'application/pkix-pkipath', 'name': 'application',
                 'description': 'Internet Public Key Infrastructure - Certification Path'},
    '.ssml': {'file_end': '.ssml', 'type': 'application/ssml+xml', 'name': 'application',
              'description': 'Speech Synthesis Markup Language'},
    '.sema': {'file_end': '.sema', 'type': 'application/vnd.sema', 'name': 'application',
              'description': 'Secured eMail'},
    '.ppt': {'file_end': '.ppt', 'type': 'application/vnd.ms-powerpoint', 'name': 'application',
             'description': 'Microsoft PowerPoint'},
    '.odm': {'file_end': '.odm', 'type': 'application/vnd.oasis.opendocument.text-master', 'name': 'application',
             'description': 'OpenDocument Text Master'},
    '.latex': {'file_end': '.latex', 'type': 'application/x-latex', 'name': 'application', 'description': 'LaTeX'},
    '.semd': {'file_end': '.semd', 'type': 'application/vnd.semd', 'name': 'application',
              'description': 'Secured eMail'},
    '.ppd': {'file_end': '.ppd', 'type': 'application/vnd.cups-ppd', 'name': 'application',
             'description': 'Adobe PostScript Printer Description File Format'},
    '.stl': {'file_end': '.stl', 'type': 'application/vnd.ms-pki.stl', 'name': 'application',
             'description': 'Microsoft Trust UI Provider - Certificate Trust Link'},
    '.igl': {'file_end': '.igl', 'type': 'application/vnd.igloader', 'name': 'application', 'description': 'igLoader'},
    '.mbox': {'file_end': '.mbox', 'type': 'application/mbox', 'name': 'application',
              'description': 'Mbox database files'},
    '.semf': {'file_end': '.semf', 'type': 'application/vnd.semf', 'name': 'application',
              'description': 'Secured eMail'},
    '.cdmia': {'file_end': '.cdmia', 'type': 'application/cdmi-capability', 'name': 'application',
               'description': 'Cloud Data Management Interface (CDMI) - Capability'},
    '.oti': {'file_end': '.oti', 'type': 'application/vnd.oasis.opendocument.image-template', 'name': 'application',
             'description': 'OpenDocument Image Template'},
    '.cdmic': {'file_end': '.cdmic', 'type': 'application/cdmi-container', 'name': 'application',
               'description': 'Cloud Data Management Interface (CDMI) - Contaimer'},
    '.igx': {'file_end': '.igx', 'type': 'application/vnd.micrografx.igx', 'name': 'application',
             'description': 'Micrografx iGrafx Professional'},
    '.kwd': {'file_end': '.kwd', 'type': 'application/vnd.kde.kword', 'name': 'application',
             'description': 'KDE KOffice Office Suite - Kword'},
    '.apr': {'file_end': '.apr', 'type': 'application/vnd.lotus-approach', 'name': 'application',
             'description': 'Lotus Approach'},
    '.n-gage': {'file_end': '.n-gage', 'type': 'application/vnd.nokia.n-gage.symbian.install', 'name': 'application',
                'description': 'N-Gage Game Installer'},
    '.tcl': {'file_end': '.tcl', 'type': 'application/x-tcl', 'name': 'application', 'description': 'Tcl Script'},
    '.mwf': {'file_end': '.mwf', 'type': 'application/vnd.mfer', 'name': 'application',
             'description': 'Medical Waveform Encoding Format'},
    '.jam': {'file_end': '.jam', 'type': 'application/vnd.jam', 'name': 'application',
             'description': 'Lightspeed Audio Lab'},
    '.rld': {'file_end': '.rld', 'type': 'application/resource-lists-diff+xml', 'name': 'application',
             'description': 'XML Resource Lists Diff'},
    '.oth': {'file_end': '.oth', 'type': 'application/vnd.oasis.opendocument.text-web', 'name': 'application',
             'description': 'Open Document Text Web'},
    '.bz2': {'file_end': '.bz2', 'type': 'application/x-bzip2', 'name': 'application', 'description': 'Bzip2 Archive'},
    '.xar': {'file_end': '.xar', 'type': 'application/vnd.xara', 'name': 'application', 'description': 'CorelXARA'},
    '.jar': {'file_end': '.jar', 'type': 'application/java-archive', 'name': 'application',
             'description': 'Java Archive'},
    '.afp': {'file_end': '.afp', 'type': 'application/vnd.ibm.modcap', 'name': 'application',
             'description': 'MO:DCA-P'},
    '.application': {'file_end': '.application', 'type': 'application/x-ms-application', 'name': 'application',
                     'description': 'Microsoft ClickOnce'},
    '.mxf': {'file_end': '.mxf', 'type': 'application/mxf', 'name': 'application',
             'description': 'Material Exchange Format'},
    '.mxl': {'file_end': '.mxl', 'type': 'application/vnd.recordare.musicxml', 'name': 'application',
             'description': 'Recordare Applications'},
    '.mxs': {'file_end': '.mxs', 'type': 'application/vnd.triscape.mxs', 'name': 'application',
             'description': 'Triscape Map Explorer'},
    '.ufd': {'file_end': '.ufd', 'type': 'application/vnd.ufdl', 'name': 'application',
             'description': 'Universal Forms Description Language'},
    '.gram': {'file_end': '.gram', 'type': 'application/srgs', 'name': 'application',
              'description': 'Speech Recognition Grammar Specification'},
    '.jlt': {'file_end': '.jlt', 'type': 'application/vnd.hp-jlyt', 'name': 'application',
             'description': 'HP Indigo Digital Press - Job Layout Languate'},
    '.ma': {'file_end': '.ma', 'type': 'application/mathematica', 'name': 'application',
            'description': 'Mathematica Notebooks'},
    '.qam': {'file_end': '.qam', 'type': 'application/vnd.epson.quickanime', 'name': 'application',
             'description': 'QuickAnime Player'},
    '.pcurl': {'file_end': '.pcurl', 'type': 'application/vnd.curl.pcurl', 'name': 'application',
               'description': 'CURL Applet'},
    '.ser': {'file_end': '.ser', 'type': 'application/java-serialized-object', 'name': 'application',
             'description': 'Java Serialized Object'},
    '.portpkg': {'file_end': '.portpkg', 'type': 'application/vnd.macports.portpkg', 'name': 'application',
                 'description': 'MacPorts Port System'},
    '.pgp': {'file_end': '.pgp', 'type': 'application/pgp-signature', 'name': 'application',
             'description': 'Pretty Good Privacy - Signature'},
    '.xlsb': {'file_end': '.xlsb', 'type': 'application/vnd.ms-excel.sheet.binary.macroenabled.12',
              'name': 'application', 'description': 'Microsoft Excel - Binary Workbook'},
    '.nlu': {'file_end': '.nlu', 'type': 'application/vnd.neurolanguage.nlu', 'name': 'application',
             'description': 'neuroLanguage'},
    '.svd': {'file_end': '.svd', 'type': 'application/vnd.svd', 'name': 'application',
             'description': 'SourceView Document'},
    '.dp': {'file_end': '.dp', 'type': 'application/vnd.osgi.dp', 'name': 'application',
            'description': 'OSGi Deployment Package'},
    '.unityweb': {'file_end': '.unityweb', 'type': 'application/vnd.unity', 'name': 'application',
                  'description': 'Unity 3d'},
    '.123': {'file_end': '.123', 'type': 'application/vnd.lotus-1-2-3', 'name': 'application',
             'description': 'Lotus 1-2-3'},
    '.xlsm': {'file_end': '.xlsm', 'type': 'application/vnd.ms-excel.sheet.macroenabled.12', 'name': 'application',
              'description': 'Microsoft Excel - Macro-Enabled Workbook'},
    '.xbap': {'file_end': '.xbap', 'type': 'application/x-ms-xbap', 'name': 'application',
              'description': 'Microsoft XAML Browser Application'},
    '.ogx': {'file_end': '.ogx', 'type': 'application/ogg', 'name': 'application', 'description': 'Ogg'},
    '.eot': {'file_end': '.eot', 'type': 'application/vnd.ms-fontobject', 'name': 'application',
             'description': 'Microsoft Embedded OpenType'},
    '.mag': {'file_end': '.mag', 'type': 'application/vnd.ecowin.chart', 'name': 'application',
             'description': 'EcoWin Chart'},
    '.iif': {'file_end': '.iif', 'type': 'application/vnd.shana.informed.interchange', 'name': 'application',
             'description': 'Shana Informed Filler'},
    '.atx': {'file_end': '.atx', 'type': 'application/vnd.antix.game-component', 'name': 'application',
             'description': 'Antix Game Player'},
    '.mny': {'file_end': '.mny', 'type': 'application/x-msmoney', 'name': 'application',
             'description': 'Microsoft Money'},
    '.ghf': {'file_end': '.ghf', 'type': 'application/vnd.groove-help', 'name': 'application',
             'description': 'Groove - Help'},
    '.cpio': {'file_end': '.cpio', 'type': 'application/x-cpio', 'name': 'application', 'description': 'CPIO Archive'},
    '.setreg': {'file_end': '.setreg', 'type': 'application/set-registration-initiation', 'name': 'application',
                'description': 'Secure Electronic Transaction - Registration'},
    '.atc': {'file_end': '.atc', 'type': 'application/vnd.acucorp', 'name': 'application', 'description': 'ACU Cobol'},
    '.rif': {'file_end': '.rif', 'type': 'application/reginfo+xml', 'name': 'application',
             'description': 'IMS Networks'},
    '.scq': {'file_end': '.scq', 'type': 'application/scvp-cv-request', 'name': 'application',
             'description': 'Server-Based Certificate Validation Protocol - Validation Request'},
    '.scs': {'file_end': '.scs', 'type': 'application/scvp-cv-response', 'name': 'application',
             'description': 'Server-Based Certificate Validation Protocol - Validation Response'},
    '.scm': {'file_end': '.scm', 'type': 'application/vnd.lotus-screencam', 'name': 'application',
             'description': 'Lotus Screencam'},
    '.xfdl': {'file_end': '.xfdl', 'type': 'application/vnd.xfdl', 'name': 'application',
              'description': 'Extensible Forms Description Language'},
    '.scd': {'file_end': '.scd', 'type': 'application/x-msschedule', 'name': 'application',
             'description': 'Microsoft Schedule+'},
    '.xfdf': {'file_end': '.xfdf', 'type': 'application/vnd.adobe.xfdf', 'name': 'application',
              'description': 'Adobe XML Forms Data Format'},
    '.xlam': {'file_end': '.xlam', 'type': 'application/vnd.ms-excel.addin.macroenabled.12', 'name': 'application',
              'description': 'Microsoft Excel - Add-In File'},
    '.aab': {'file_end': '.aab', 'type': 'application/x-authorware-bin', 'name': 'application',
             'description': 'Adobe (Macropedia) Authorware - Binary File'},
    '.sda': {'file_end': '.sda', 'type': 'application/vnd.stardivision.draw', 'name': 'application',
             'description': 'StarOffice - Draw'},
    '.aam': {'file_end': '.aam', 'type': 'application/x-authorware-map', 'name': 'application',
             'description': 'Adobe (Macropedia) Authorware - Map'},
    '.sdc': {'file_end': '.sdc', 'type': 'application/vnd.stardivision.calc', 'name': 'application',
             'description': 'StarOffice - Calc'},
    '.sdd': {'file_end': '.sdd', 'type': 'application/vnd.stardivision.impress', 'name': 'application',
             'description': 'StarOffice - Impress'},
    '.rp9': {'file_end': '.rp9', 'type': 'application/vnd.cloanto.rp9', 'name': 'application',
             'description': 'RetroPlatform Player'},
    '.js': {'file_end': '.js', 'type': 'application/javascript', 'name': 'application', 'description': 'JavaScript'},
    '.aas': {'file_end': '.aas', 'type': 'application/x-authorware-seg', 'name': 'application',
             'description': 'Adobe (Macropedia) Authorware - Segment File'},
    '.sdp': {'file_end': '.sdp', 'type': 'application/sdp', 'name': 'application',
             'description': 'Session Description Protocol'},
    '.sdw': {'file_end': '.sdw', 'type': 'application/vnd.stardivision.writer', 'name': 'application',
             'description': 'StarOffice - Writer'},
    '.plb': {'file_end': '.plb', 'type': 'application/vnd.3gpp.pic-bw-large', 'name': 'application',
             'description': '3rd Generation Partnership Project - Pic Large'},
    '.plc': {'file_end': '.plc', 'type': 'application/vnd.mobius.plc', 'name': 'application',
             'description': 'Mobius Management Systems - Policy Definition Language File'},
    '.plf': {'file_end': '.plf', 'type': 'application/vnd.pocketlearn', 'name': 'application',
             'description': 'PocketLearn Viewers'},
    '.ez3': {'file_end': '.ez3', 'type': 'application/vnd.ezpix-package', 'name': 'application',
             'description': 'EZPix Secure Photo Album'},
    '.wtb': {'file_end': '.wtb', 'type': 'application/vnd.webturbo', 'name': 'application', 'description': 'WebTurbo'},
    '.msf': {'file_end': '.msf', 'type': 'application/vnd.epson.msf', 'name': 'application',
             'description': 'QUASS Stream Player'},
    '.pls': {'file_end': '.pls', 'type': 'application/pls+xml', 'name': 'application',
             'description': 'Pronunciation Lexicon Specification'},
    '.flo': {'file_end': '.flo', 'type': 'application/vnd.micrografx.flo', 'name': 'application',
             'description': 'Micrografx'},
    '.msl': {'file_end': '.msl', 'type': 'application/vnd.mobius.msl', 'name': 'application',
             'description': 'Mobius Management Systems - Script Language'},
    '.qxd': {'file_end': '.qxd', 'type': 'application/vnd.quark.quarkxpress', 'name': 'application',
             'description': 'QuarkXpress'},
    '.pcf': {'file_end': '.pcf', 'type': 'application/x-font-pcf', 'name': 'application',
             'description': 'Portable Compiled Format'},
    '.potm': {'file_end': '.potm', 'type': 'application/vnd.ms-powerpoint.template.macroenabled.12',
              'name': 'application', 'description': 'Micosoft PowerPoint - Macro-Enabled Template File'},
    '.7z': {'file_end': '.7z', 'type': 'application/x-7z-compressed', 'name': 'application', 'description': '7-Zip'},
    '.pcl': {'file_end': '.pcl', 'type': 'application/vnd.hp-pcl', 'name': 'application',
             'description': 'HP Printer Command Language'},
    '.cpt': {'file_end': '.cpt', 'type': 'application/mac-compactpro', 'name': 'application',
             'description': 'Compact Pro'},
    '.mdb': {'file_end': '.mdb', 'type': 'application/x-msaccess', 'name': 'application',
             'description': 'Microsoft Access'},
    '.cmp': {'file_end': '.cmp', 'type': 'application/vnd.yellowriver-custom-menu', 'name': 'application',
             'description': 'CustomMenu'},
    '.potx': {'file_end': '.potx', 'type': 'application/vnd.openxmlformats-officedocument.presentationml.template',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Presentation Template'},
    '.zir': {'file_end': '.zir', 'type': 'application/vnd.zul', 'name': 'application',
             'description': 'Z.U.L. Geometry'},
    '.zip': {'file_end': '.zip', 'type': 'application/zip', 'name': 'application', 'description': 'Zip Archive'},
    '.clkk': {'file_end': '.clkk', 'type': 'application/vnd.crick.clicker.keyboard', 'name': 'application',
              'description': 'CrickSoftware - Clicker - Keyboard'},
    '.ggb': {'file_end': '.ggb', 'type': 'application/vnd.geogebra.file', 'name': 'application',
             'description': 'GeoGebra'},
    '.class': {'file_end': '.class', 'type': 'application/java-vm', 'name': 'application',
               'description': 'Java Bytecode File'},
    '.mmf': {'file_end': '.mmf', 'type': 'application/vnd.smaf', 'name': 'application', 'description': 'SMAF File'},
    '.xer': {'file_end': '.xer', 'type': 'application/patch-ops-error+xml', 'name': 'application',
             'description': 'XML Patch Framework'},
    '.vsd': {'file_end': '.vsd', 'type': 'application/vnd.visio', 'name': 'application',
             'description': 'Microsoft Visio'},
    '.clkx': {'file_end': '.clkx', 'type': 'application/vnd.crick.clicker', 'name': 'application',
              'description': 'CrickSoftware - Clicker'},
    '.clkw': {'file_end': '.clkw', 'type': 'application/vnd.crick.clicker.wordbank', 'name': 'application',
              'description': 'CrickSoftware - Clicker - Wordbank'},
    '.xo': {'file_end': '.xo', 'type': 'application/vnd.olpc-sugar', 'name': 'application',
            'description': 'Sugar Linux Application Bundle'},
    '.clkt': {'file_end': '.clkt', 'type': 'application/vnd.crick.clicker.template', 'name': 'application',
              'description': 'CrickSoftware - Clicker - Template'},
    '.aso': {'file_end': '.aso', 'type': 'application/vnd.accpac.simply.aso', 'name': 'application',
             'description': 'Simply Accounting'},
    '.clkp': {'file_end': '.clkp', 'type': 'application/vnd.crick.clicker.palette', 'name': 'application',
              'description': 'CrickSoftware - Clicker - Palette'},
    '.sh': {'file_end': '.sh', 'type': 'application/x-sh', 'name': 'application', 'description': 'Bourne Shell Script'},
    '.sm': {'file_end': '.sm', 'type': 'application/vnd.stepmania.stepchart', 'name': 'application',
            'description': 'StepMania'},
    '.wbs': {'file_end': '.wbs', 'type': 'application/vnd.criticaltools.wbs+xml', 'name': 'application',
             'description': 'Critical Tools - PERT Chart EXPERT'},
    '.sc': {'file_end': '.sc', 'type': 'application/vnd.ibm.secure-container', 'name': 'application',
            'description': 'IBM Electronic Media Management System - Secure Container'},
    '.xls': {'file_end': '.xls', 'type': 'application/vnd.ms-excel', 'name': 'application',
             'description': 'Microsoft Excel'},
    '.cii': {'file_end': '.cii', 'type': 'application/vnd.anser-web-certificate-issue-initiation',
             'name': 'application', 'description': 'ANSER-WEB Terminal Client - Certificate Issue'},
    '.st': {'file_end': '.st', 'type': 'application/vnd.sailingtracker.track', 'name': 'application',
            'description': 'SailingTracker'},
    '.cil': {'file_end': '.cil', 'type': 'application/vnd.ms-artgalry', 'name': 'application',
             'description': 'Microsoft Artgalry'},
    '.gtm': {'file_end': '.gtm', 'type': 'application/vnd.groove-tool-message', 'name': 'application',
             'description': 'Groove - Tool Message'},
    '.trm': {'file_end': '.trm', 'type': 'application/x-msterminal', 'name': 'application',
             'description': 'Microsoft Windows Terminal Services'},
    '.onetoc': {'file_end': '.onetoc', 'type': 'application/onenote', 'name': 'application',
                'description': 'Microsoft OneNote'},
    '.pub': {'file_end': '.pub', 'type': 'application/x-mspublisher', 'name': 'application',
             'description': 'Microsoft Publisher'},
    '.imp': {'file_end': '.imp', 'type': 'application/vnd.accpac.simply.imp', 'name': 'application',
             'description': 'Simply Accounting - Data Import'},
    '.ims': {'file_end': '.ims', 'type': 'application/vnd.ms-ims', 'name': 'application',
             'description': 'Microsoft Class Server'},
    '.tra': {'file_end': '.tra', 'type': 'application/vnd.trueapp', 'name': 'application', 'description': 'True BASIC'},
    '.fsc': {'file_end': '.fsc', 'type': 'application/vnd.fsc.weblaunch', 'name': 'application',
             'description': 'Friendly Software Corporation'},
    '.ifm': {'file_end': '.ifm', 'type': 'application/vnd.shana.informed.formdata', 'name': 'application',
             'description': 'Shana Informed Filler'},
    '.sgl': {'file_end': '.sgl', 'type': 'application/vnd.stardivision.writer-global', 'name': 'application',
             'description': 'StarOffice - Writer (Global)'},
    '.musicxml': {'file_end': '.musicxml', 'type': 'application/vnd.recordare.musicxml+xml', 'name': 'application',
                  'description': 'Recordare Applications'},
    '.lbd': {'file_end': '.lbd', 'type': 'application/vnd.llamagraphics.life-balance.desktop', 'name': 'application',
             'description': 'Life Balance - Desktop Edition'},
    '.lbe': {'file_end': '.lbe', 'type': 'application/vnd.llamagraphics.life-balance.exchange+xml',
             'name': 'application', 'description': 'Life Balance - Exchange Format'},
    '.woff': {'file_end': '.woff', 'type': 'application/x-font-woff', 'name': 'application',
              'description': 'Web Open Font Format'},
    '.mvb': {'file_end': '.mvb', 'type': 'application/x-msmediaview', 'name': 'application',
             'description': 'Microsoft MediaView'},
    '.les': {'file_end': '.les', 'type': 'application/vnd.hhe.lesson-player', 'name': 'application',
             'description': 'Archipelago Lesson Player'},
    '.rms': {'file_end': '.rms', 'type': 'application/vnd.jcp.javame.midlet-rms', 'name': 'application',
             'description': 'Mobile Information Device Profile'},
    '.mets': {'file_end': '.mets', 'type': 'application/mets+xml', 'name': 'application',
              'description': 'Metadata Encoding and Transmission Standard'},
    '.rdf': {'file_end': '.rdf', 'type': 'application/rdf+xml', 'name': 'application',
             'description': 'Resource Description Framework'},
    '.sxw': {'file_end': '.sxw', 'type': 'application/vnd.sun.xml.writer', 'name': 'application',
             'description': 'OpenOffice - Writer (Text - HTML)'},
    '.nc': {'file_end': '.nc', 'type': 'application/x-netcdf', 'name': 'application',
            'description': 'Network Common Data Form (NetCDF)'},
    '.fzs': {'file_end': '.fzs', 'type': 'application/vnd.fuzzysheet', 'name': 'application',
             'description': 'FuzzySheet'},
    '.sxm': {'file_end': '.sxm', 'type': 'application/vnd.sun.xml.math', 'name': 'application',
             'description': 'OpenOffice - Math (Formula)'},
    '.mseq': {'file_end': '.mseq', 'type': 'application/vnd.mseq', 'name': 'application',
              'description': '3GPP MSEQ File'},
    '.sxi': {'file_end': '.sxi', 'type': 'application/vnd.sun.xml.impress', 'name': 'application',
             'description': 'OpenOffice - Impress (Presentation)'},
    '.aep': {'file_end': '.aep', 'type': 'application/vnd.audiograph', 'name': 'application',
             'description': 'Audiograph'},
    '.bin': {'file_end': '.bin', 'type': 'application/octet-stream', 'name': 'application',
             'description': 'Binary Data'},
    '.sxg': {'file_end': '.sxg', 'type': 'application/vnd.sun.xml.writer.global', 'name': 'application',
             'description': 'OpenOffice - Writer (Text - HTML)'},
    '.sxc': {'file_end': '.sxc', 'type': 'application/vnd.sun.xml.calc', 'name': 'application',
             'description': 'OpenOffice - Calc (Spreadsheet)'},
    '.ac': {'file_end': '.ac', 'type': 'application/pkix-attr-cert', 'name': 'application',
            'description': 'Attribute Certificate'},
    '.pptm': {'file_end': '.pptm', 'type': 'application/vnd.ms-powerpoint.presentation.macroenabled.12',
              'name': 'application', 'description': 'Microsoft PowerPoint - Macro-Enabled Presentation File'},
    '.itp': {'file_end': '.itp', 'type': 'application/vnd.shana.informed.formtemplate', 'name': 'application',
             'description': 'Shana Informed Filler'},
    '.xltm': {'file_end': '.xltm', 'type': 'application/vnd.ms-excel.template.macroenabled.12', 'name': 'application',
              'description': 'Microsoft Excel - Macro-Enabled Template File'},
    '.ai': {'file_end': '.ai', 'type': 'application/postscript', 'name': 'application', 'description': 'PostScript'},
    '.rcprofile': {'file_end': '.rcprofile', 'type': 'application/vnd.ipunplugged.rcprofile', 'name': 'application',
                   'description': 'IP Unplugged Roaming Client'},
    '.fe_launch': {'file_end': '.fe_launch', 'type': 'application/vnd.denovo.fcselayout-link', 'name': 'application',
                   'description': 'FCS Express Layout Link'},
    '.xltx': {'file_end': '.xltx', 'type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Spreadsheet Teplate'},
    '.oxt': {'file_end': '.oxt', 'type': 'application/vnd.openofficeorg.extension', 'name': 'application',
             'description': 'Open Office Extension'},
    '.pptx': {'file_end': '.pptx', 'type': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Presentation'},
    '.wpl': {'file_end': '.wpl', 'type': 'application/vnd.ms-wpl', 'name': 'application',
             'description': 'Microsoft Windows Media Player Playlist'},
    '.xenc': {'file_end': '.xenc', 'type': 'application/xenc+xml', 'name': 'application',
              'description': 'XML Encryption Syntax and Processing'},
    '.gnumeric': {'file_end': '.gnumeric', 'type': 'application/x-gnumeric', 'name': 'application',
                  'description': 'Gnumeric'},
    '.mods': {'file_end': '.mods', 'type': 'application/mods+xml', 'name': 'application',
              'description': 'Metadata Object Description Schema'},
    '.docm': {'file_end': '.docm', 'type': 'application/vnd.ms-word.document.macroenabled.12', 'name': 'application',
              'description': 'Micosoft Word - Macro-Enabled Document'},
    '.x3d': {'file_end': '.x3d', 'type': 'application/vnd.hzn-3d-crossword', 'name': 'application',
             'description': '3D Crossword Plugin'},
    '.xap': {'file_end': '.xap', 'type': 'application/x-silverlight-app', 'name': 'application',
             'description': 'Microsoft Silverlight'},
    '.igm': {'file_end': '.igm', 'type': 'application/vnd.insors.igm', 'name': 'application',
             'description': 'IOCOM Visimeet'},
    '.pfr': {'file_end': '.pfr', 'type': 'application/font-tdpfr', 'name': 'application',
             'description': 'Portable Font Resource'},
    '.docx': {'file_end': '.docx', 'type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
              'name': 'application', 'description': 'Microsoft Office - OOXML - Word Document'},
    '.zmm': {'file_end': '.zmm', 'type': 'application/vnd.handheld-entertainment+xml', 'name': 'application',
             'description': 'ZVUE Media Manager'},
    '.sv4crc': {'file_end': '.sv4crc', 'type': 'application/x-sv4crc', 'name': 'application',
                'description': 'System V Release 4 CPIO Checksum Data'},
    '.cmc': {'file_end': '.cmc', 'type': 'application/vnd.cosmocaller', 'name': 'application',
             'description': 'CosmoCaller'},
    '.pvb': {'file_end': '.pvb', 'type': 'application/vnd.3gpp.pic-bw-var', 'name': 'application',
             'description': '3rd Generation Partnership Project - Pic Var'},
    '.mif': {'file_end': '.mif', 'type': 'application/vnd.mif', 'name': 'application',
             'description': 'FrameMaker Interchange Format'},
    '.chat': {'file_end': '.chat', 'type': 'application/x-chat', 'name': 'application', 'description': 'pIRCh'},
    '.kml': {'file_end': '.kml', 'type': 'application/vnd.google-earth.kml+xml', 'name': 'application',
             'description': 'Google Earth - KML'},
    '.gph': {'file_end': '.gph', 'type': 'application/vnd.flographit', 'name': 'application',
             'description': 'NpGraphIt'},
    '.sfd-hdstx': {'file_end': '.sfd-hdstx', 'type': 'application/vnd.hydrostatix.sof-data', 'name': 'application',
                   'description': 'Hydrostatix Master Suite'},
    '.ncx': {'file_end': '.ncx', 'type': 'application/x-dtbncx+xml', 'name': 'application',
             'description': 'Navigation Control file for XML (for ePub)'},
    '.wg': {'file_end': '.wg', 'type': 'application/vnd.pmi.widget', 'name': 'application',
            'description': "Qualcomm's Plaza Mobile Internet"},
    '.kmz': {'file_end': '.kmz', 'type': 'application/vnd.google-earth.kmz', 'name': 'application',
             'description': 'Google Earth - Zipped KML'},
    '.teacher': {'file_end': '.teacher', 'type': 'application/vnd.smart.teacher', 'name': 'application',
                 'description': 'SMART Technologies Apps'},
    '.dis': {'file_end': '.dis', 'type': 'application/vnd.mobius.dis', 'name': 'application',
             'description': 'Mobius Management Systems - Distribution Database'},
    '.dir': {'file_end': '.dir', 'type': 'application/x-director', 'name': 'application',
             'description': 'Adobe Shockwave Player'},
    '.setpay': {'file_end': '.setpay', 'type': 'application/set-payment-initiation', 'name': 'application',
                'description': 'Secure Electronic Transaction - Payment'},
    '.snf': {'file_end': '.snf', 'type': 'application/x-font-snf', 'name': 'application',
             'description': 'Server Normal Format'},
    '.mscml': {'file_end': '.mscml', 'type': 'application/mediaservercontrol+xml', 'name': 'application',
               'description': 'Media Server Control Markup Language'},
    '.mmd': {'file_end': '.mmd', 'type': 'application/vnd.chipnuts.karaoke-mmd', 'name': 'application',
             'description': 'Karaoke on Chipnuts Chipsets'},
    '.lasxml': {'file_end': '.lasxml', 'type': 'application/vnd.las.las+xml', 'name': 'application',
                'description': 'Laser App Enterprise'},
    '.ftc': {'file_end': '.ftc', 'type': 'application/vnd.fluxtime.clip', 'name': 'application',
             'description': 'FluxTime Clip'},
    '.fti': {'file_end': '.fti', 'type': 'application/vnd.anser-web-funds-transfer-initiation', 'name': 'application',
             'description': 'ANSER-WEB Terminal Client - Web Funds Transfer'},
    '.mads': {'file_end': '.mads', 'type': 'application/mads+xml', 'name': 'application',
              'description': 'Metadata Authority Description Schema'}}, 'video': {
    '.flv': {'file_end': '.flv', 'type': 'video/x-flv', 'name': 'video', 'description': 'Flash Video'},
    '.3g2': {'file_end': '.3g2', 'type': 'video/3gpp2', 'name': 'video', 'description': '3GP2'},
    '.fli': {'file_end': '.fli', 'type': 'video/x-fli', 'name': 'video', 'description': 'FLI/FLC Animation Format'},
    '.mxu': {'file_end': '.mxu', 'type': 'video/vnd.mpegurl', 'name': 'video', 'description': 'MPEG Url'},
    '.jpm': {'file_end': '.jpm', 'type': 'video/jpm', 'name': 'video',
             'description': 'JPEG 2000 Compound Image File Format'},
    '.mpeg': {'file_end': '.mpeg', 'type': 'video/mpeg', 'name': 'video', 'description': 'MPEG Video'},
    '.f4v': {'file_end': '.f4v', 'type': 'video/x-f4v', 'name': 'video', 'description': 'Flash Video'},
    '.h263': {'file_end': '.h263', 'type': 'video/h263', 'name': 'video', 'description': 'H.263'},
    '.h261': {'file_end': '.h261', 'type': 'video/h261', 'name': 'video', 'description': 'H.261'},
    '.mj2': {'file_end': '.mj2', 'type': 'video/mj2', 'name': 'video', 'description': 'Motion JPEG 2000'},
    '.h264': {'file_end': '.h264', 'type': 'video/h264', 'name': 'video', 'description': 'H.264'},
    '.uvm': {'file_end': '.uvm', 'type': 'video/vnd.dece.mobile', 'name': 'video', 'description': 'DECE Mobile Video'},
    '.asf': {'file_end': '.asf', 'type': 'video/x-ms-asf', 'name': 'video',
             'description': 'Microsoft Advanced Systems Format (ASF)'},
    '.qt': {'file_end': '.qt', 'type': 'video/quicktime', 'name': 'video', 'description': 'Quicktime Video'},
    '.avi': {'file_end': '.avi', 'type': 'video/x-msvideo', 'name': 'video',
             'description': 'Audio Video Interleave (AVI)'},
    '.uvh': {'file_end': '.uvh', 'type': 'video/vnd.dece.hd', 'name': 'video',
             'description': 'DECE High Definition Video'},
    '.uvu': {'file_end': '.uvu', 'type': 'video/vnd.uvvu.mp4', 'name': 'video', 'description': 'DECE MP4'},
    '.uvv': {'file_end': '.uvv', 'type': 'video/vnd.dece.video', 'name': 'video', 'description': 'DECE Video'},
    '.webm': {'file_end': '.webm', 'type': 'video/webm', 'name': 'video',
              'description': 'Open Web Media Project - Video'},
    '.uvp': {'file_end': '.uvp', 'type': 'video/vnd.dece.pd', 'name': 'video', 'description': 'DECE PD Video'},
    '.uvs': {'file_end': '.uvs', 'type': 'video/vnd.dece.sd', 'name': 'video', 'description': 'DECE SD Video'},
    '.wm': {'file_end': '.wm', 'type': 'video/x-ms-wm', 'name': 'video', 'description': 'Microsoft Windows Media'},
    '.movie': {'file_end': '.movie', 'type': 'video/x-sgi-movie', 'name': 'video', 'description': 'SGI Movie'},
    '.3gp': {'file_end': '.3gp', 'type': 'video/3gpp', 'name': 'video', 'description': '3GP'},
    '.viv': {'file_end': '.viv', 'type': 'video/vnd.vivo', 'name': 'video', 'description': 'Vivo'},
    '.fvt': {'file_end': '.fvt', 'type': 'video/vnd.fvt', 'name': 'video', 'description': 'FAST Search & Transfer ASA'},
    '.ogv': {'file_end': '.ogv', 'type': 'video/ogg', 'name': 'video', 'description': 'Ogg Video'},
    '.m4v': {'file_end': '.m4v', 'type': 'video/x-m4v', 'name': 'video', 'description': 'M4v'},
    '.wmx': {'file_end': '.wmx', 'type': 'video/x-ms-wmx', 'name': 'video',
             'description': 'Microsoft Windows Media Audio/Video Playlist'},
    '.jpgv': {'file_end': '.jpgv', 'type': 'video/jpeg', 'name': 'video', 'description': 'JPGVideo'},
    '.pyv': {'file_end': '.pyv', 'type': 'video/vnd.ms-playready.media.pyv', 'name': 'video',
             'description': 'Microsoft PlayReady Ecosystem Video'},
    '.mp4': {'file_end': '.mp4', 'type': 'video/mp4', 'name': 'video', 'description': 'MPEG-4 Video'},
    '.wmv': {'file_end': '.wmv', 'type': 'video/x-ms-wmv', 'name': 'video',
             'description': 'Microsoft Windows Media Video'},
    '.wvx': {'file_end': '.wvx', 'type': 'video/x-ms-wvx', 'name': 'video',
             'description': 'Microsoft Windows Media Video Playlist'}}, 'model': {
    '.dae': {'file_end': '.dae', 'type': 'model/vnd.collada+xml', 'name': 'model', 'description': 'COLLADA'},
    '.gdl': {'file_end': '.gdl', 'type': 'model/vnd.gdl', 'name': 'model',
             'description': 'Geometric Description Language (GDL)'},
    '.wrl': {'file_end': '.wrl', 'type': 'model/vrml', 'name': 'model',
             'description': 'Virtual Reality Modeling Language'},
    '.gtw': {'file_end': '.gtw', 'type': 'model/vnd.gtw', 'name': 'model', 'description': 'Gen-Trix Studio'},
    '.vtu': {'file_end': '.vtu', 'type': 'model/vnd.vtu', 'name': 'model', 'description': 'Virtue VTU'},
    '.mts': {'file_end': '.mts', 'type': 'model/vnd.mts', 'name': 'model', 'description': 'Virtue MTS'},
    '.dwf': {'file_end': '.dwf', 'type': 'model/vnd.dwf', 'name': 'model',
             'description': 'Autodesk Design Web Format (DWF)'},
    '.igs': {'file_end': '.igs', 'type': 'model/iges', 'name': 'model',
             'description': 'Initial Graphics Exchange Specification (IGES)'},
    '.msh': {'file_end': '.msh', 'type': 'model/mesh', 'name': 'model', 'description': 'Mesh Data Type'}}, 'audio': {
    '.ecelp9600': {'file_end': '.ecelp9600', 'type': 'audio/vnd.nuera.ecelp9600', 'name': 'audio',
                   'description': 'Nuera ECELP 9600'},
    '.adp': {'file_end': '.adp', 'type': 'audio/adpcm', 'name': 'audio',
             'description': 'Adaptive differential pulse-code modulation'},
    '.mpga': {'file_end': '.mpga', 'type': 'audio/mpeg', 'name': 'audio', 'description': 'MPEG Audio'},
    '.m3u': {'file_end': '.m3u', 'type': 'audio/x-mpegurl', 'name': 'audio',
             'description': 'M3U (Multimedia Playlist)'},
    '.ram': {'file_end': '.ram', 'type': 'audio/x-pn-realaudio', 'name': 'audio', 'description': 'Real Audio Sound'},
    '.mid': {'file_end': '.mid', 'type': 'audio/midi', 'name': 'audio',
             'description': 'MIDI - Musical Instrument Digital Interface'},
    '.rip': {'file_end': '.rip', 'type': 'audio/vnd.rip', 'name': 'audio', 'description': "Hit'n'Mix"},
    '.lvp': {'file_end': '.lvp', 'type': 'audio/vnd.lucent.voice', 'name': 'audio', 'description': 'Lucent Voice'},
    '.rmp': {'file_end': '.rmp', 'type': 'audio/x-pn-realaudio-plugin', 'name': 'audio',
             'description': 'Real Audio Sound'},
    '.ecelp7470': {'file_end': '.ecelp7470', 'type': 'audio/vnd.nuera.ecelp7470', 'name': 'audio',
                   'description': 'Nuera ECELP 7470'},
    '.uva': {'file_end': '.uva', 'type': 'audio/vnd.dece.audio', 'name': 'audio', 'description': 'DECE Audio'},
    '.aac': {'file_end': '.aac', 'type': 'audio/x-aac', 'name': 'audio', 'description': 'Advanced Audio Coding (AAC)'},
    '.dra': {'file_end': '.dra', 'type': 'audio/vnd.dra', 'name': 'audio', 'description': 'DRA Audio'},
    '.eol': {'file_end': '.eol', 'type': 'audio/vnd.digital-winds', 'name': 'audio',
             'description': 'Digital Winds Music'},
    '.dts': {'file_end': '.dts', 'type': 'audio/vnd.dts', 'name': 'audio', 'description': 'DTS Audio'},
    '.mp4a': {'file_end': '.mp4a', 'type': 'audio/mp4', 'name': 'audio', 'description': 'MPEG-4 Audio'},
    '.weba': {'file_end': '.weba', 'type': 'audio/webm', 'name': 'audio',
              'description': 'Open Web Media Project - Audio'},
    '.aif': {'file_end': '.aif', 'type': 'audio/x-aiff', 'name': 'audio',
             'description': 'Audio Interchange File Format'},
    '.pya': {'file_end': '.pya', 'type': 'audio/vnd.ms-playready.media.pya', 'name': 'audio',
             'description': 'Microsoft PlayReady Ecosystem'},
    '.wma': {'file_end': '.wma', 'type': 'audio/x-ms-wma', 'name': 'audio',
             'description': 'Microsoft Windows Media Audio'},
    '.ecelp4800': {'file_end': '.ecelp4800', 'type': 'audio/vnd.nuera.ecelp4800', 'name': 'audio',
                   'description': 'Nuera ECELP 4800'},
    '.wav': {'file_end': '.wav', 'type': 'audio/x-wav', 'name': 'audio',
             'description': 'Waveform Audio File Format (WAV)'},
    '.au': {'file_end': '.au', 'type': 'audio/basic', 'name': 'audio', 'description': 'Sun Audio - Au file format'},
    '.dtshd': {'file_end': '.dtshd', 'type': 'audio/vnd.dts.hd', 'name': 'audio',
               'description': 'DTS High Definition Audio'},
    '.oga': {'file_end': '.oga', 'type': 'audio/ogg', 'name': 'audio', 'description': 'Ogg Audio'},
    '.wax': {'file_end': '.wax', 'type': 'audio/x-ms-wax', 'name': 'audio',
             'description': 'Microsoft Windows Media Audio Redirector'}}, 'message': {
    '.eml': {'file_end': '.eml', 'type': 'message/rfc822', 'name': 'message', 'description': 'Email Message'}}}

    def __init__(self, environ, start_response, session, logger):
        """
        Constructor for the class.
        :param environ:        WSGI enviroment
        :param start_response: WSGI start_respose
        :param session:        Beaker session
        :param logger:         Class to perform logging.
        """
        self.environ = environ
        self.start_response = start_response
        self.session = session
        self.logger = logger

    @staticmethod
    def transform_path(path):
        """
        Help method to point robots.txt to the path to the file.
        :param path: Requested path.
        :return: The path to robots.txt if requested, otherwise the unchanged path.
        """
        if path == "robots.txt":
            return "static/robots.txt"
        return path

    def verify_static(self, path):
        """
        Verifies if this is a file that should be in the static folder.
        :param path: Requested resource with path.
        :return: True if the file should be in the static folder, otherwise false.
        """
        path = self.transform_path(path)
        if path.startswith("static/"):
            return True
        return False

    def handle_static(self, path):
        """
        Renders static pages.
        :param path: Requested resource.
        :return: WSGI response.
        """

        path = self.transform_path(path)

        self.logger.info("[static]sending: %s" % (path,))
        try:
            ending = '.' + path[::-1].split('.')[0][::-1]
            try:
                text = open(self.GLOBAL_STATIC + path).read()
            except IOError:
                text = open(path).read()
            if ending == ".ico":
                self.start_response('200 OK', [('Content-Type', "image/x-icon")])
            elif ending == ".html":
                self.start_response('200 OK', [('Content-Type', 'text/html')])
            elif ending == ".json":
                self.start_response('200 OK', [('Content-Type', 'application/json')])
            elif ending == ".txt":
                self.start_response('200 OK', [('Content-Type', 'text/plain')])
            elif ending == ".css":
                self.start_response('200 OK', [('Content-Type', 'text/css')])
            elif ending == ".js":
                self.start_response('200 OK', [('Content-Type', 'text/javascript')])
            elif ending == ".xml":
                self.start_response('200 OK', [('Content-Type', 'text/xml')])
            else:
                for key, map in self.mime_map.iteritems():
                    if ending in map:
                        self.start_response('200 OK', [('Content-Type', map[ending]["type"])])
            return [text]
        except IOError:
            return self.http404()

    def log_response(self, response):
        """
        Logs a WSGI response.
        :param response: WSGI response.
        """
        self.logger.info("response:")
        self.logger.info(response)

    def log_request(self):
        """
        Logs the WSGI request.
        """
        query = self.query_dict()
        if "CONTENT_TYPE" in self.environ:
            self.logger.info("CONTENT_TYPE:" + self.environ["CONTENT_TYPE"])
        if "REQUEST_METHOD" in self.environ:
            self.logger.info("CONTENT_TYPE:" + self.environ["REQUEST_METHOD"])
        self.logger.info("Path:" + self.path())
        self.logger.info("Query:")
        self.logger.info(query)

    @staticmethod
    def query_dictionary(environ):
        """
        Retrieves a dictionary with query parameters.
        Does not matter if the query parameters are POST or GET.
        Can handle JSON and URL encoded POST, otherwise the body is returned in a dictionare with the key post.
        :param environ: The wsgi enviroment.
        :return: A dictionary with query parameters.
        """
        qs = {}
        query = environ.get("QUERY_STRING", "")
        if not query:
            try:
                length = int(environ["CONTENT_LENGTH"])
                body = environ["wsgi.input"].read(length)
                environ['wsgi.input'] = StringIO(body)
                if "CONTENT_TYPE" in environ and "application/json" in environ["CONTENT_TYPE"]:
                    return json.loads(body)
                elif "CONTENT_TYPE" in environ and environ["CONTENT_TYPE"] == "application/x-www-form-urlencoded":
                    return parse_qs(body)
                else:
                    return {"post": body}
            except:
                pass

        else:
            qs = dict((k, v if len(v) > 1 else v[0]) for k, v in
                      parse_qs(query).iteritems())
        return qs

    def query_dict(self):
        """
        Retrieves a dictionary with query parameters.
        Does not matter if the query parameters are POST or GET.
        Can handle JSON and URL encoded POST, otherwise the body is returned in a dictionare with the key post.
        :return: A dictionary with query parameters.
        """
        return HttpHandler.query_dictionary(self.environ)

    def path(self):
        """
        Get the requested path.
        :return: Path as a string
        """
        return self.environ.get('PATH_INFO', '').lstrip('/')

    def http404(self):
        """
        WSGI HTTP 404 response.
        :return WSGI response for HTTP 404.
        """
        resp = NotFound()
        return resp(self.environ, self.start_response)


class Response(object):
    _template = None
    _status = '200 OK'
    _content_type = 'text/html'
    _mako_template = None
    _mako_lookup = None

    def __init__(self, message=None, **kwargs):
        self.status = kwargs.get('status', self._status)
        self.response = kwargs.get('response', self._response)
        self.template = kwargs.get('template', self._template)
        self.mako_template = kwargs.get('mako_template', self._mako_template)
        self.mako_lookup = kwargs.get('template_lookup', self._mako_lookup)

        self.message = message

        self.headers = kwargs.get('headers', [])
        _content_type = kwargs.get('content', self._content_type)
        self.headers.append(('Content-type', _content_type))

    def __call__(self, environ, start_response, **kwargs):
        start_response(self.status, self.headers)
        return self.response(self.message or geturl(environ), **kwargs)

    def _response(self, message="", **argv):
        if self.template:
            if ("Content-type", 'application/json') in self.headers:
                return [message]
            else:
                return [str(self.template % message)]
        elif self.mako_lookup and self.mako_template:
            argv["message"] = message
            mte = self.mako_lookup.get_template(self.mako_template)
            return [mte.render(**argv)]
        else:
            return [message]


class Created(Response):
    _status = "201 Created"


class Redirect(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
                '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
                '</body>\n</html>'
    _status = '302 Found'

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))


class SeeOther(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
                '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
                '</body>\n</html>'
    _status = '303 See Other'

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))


class Forbidden(Response):
    _status = '403 Forbidden'
    _template = "<html>Not allowed to mess with: '%s'</html>"


class BadRequest(Response):
    _status = "400 Bad Request"
    _template = "<html>%s</html>"


class Unauthorized(Response):
    _status = "401 Unauthorized"
    _template = "<html>%s</html>"


class NotFound(Response):
    _status = '404 NOT FOUND'


class NotAcceptable(Response):
    _status = '406 Not Acceptable'


class ServiceError(Response):
    _status = '500 Internal Service Error'


R2C = {
    200: Response,
    201: Created,
    302: Redirect,
    303: SeeOther,
    400: BadRequest,
    401: Unauthorized,
    403: Forbidden,
    404: NotAcceptable,
    406: NotAcceptable,
    500: ServiceError,
}


def factory(code, message):
    return R2C[code](message)


def extract(environ, empty=False, err=False):
    """Extracts strings in form data and returns a dict.

    :param environ: WSGI environ
    :param empty: Stops on empty fields (default: Fault)
    :param err: Stops on errors in fields (default: Fault)
    """
    formdata = cgi.parse(environ['wsgi.input'], environ, empty, err)
    # Remove single entries from lists
    for key, value in formdata.iteritems():
        if len(value) == 1:
            formdata[key] = value[0]
    return formdata


def geturl(environ, query=True, path=True):
    """Rebuilds a request URL (from PEP 333).

    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)
    """
    url = [environ['wsgi.url_scheme'] + '://']
    if environ.get('HTTP_HOST'):
        url.append(environ['HTTP_HOST'])
    else:
        url.append(environ['SERVER_NAME'])
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url.append(':' + environ['SERVER_PORT'])
        else:
            if environ['SERVER_PORT'] != '80':
                url.append(':' + environ['SERVER_PORT'])
    if path:
        url.append(getpath(environ))
    if query and environ.get('QUERY_STRING'):
        url.append('?' + environ['QUERY_STRING'])
    return ''.join(url)


def getpath(environ):
    """Builds a path."""
    return ''.join([quote(environ.get('SCRIPT_NAME', '')),
                    quote(environ.get('PATH_INFO', ''))])


def _expiration(timeout, time_format=None):
    if timeout == "now":
        return time_util.instant(time_format)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, time_format=time_format)


def cookie_signature(seed, *parts):
    """Generates a cookie signature."""
    sha1 = hmac.new(seed, digestmod=hashlib.sha1)
    for part in parts:
        if part:
            sha1.update(part)
    return sha1.hexdigest()


def make_cookie(name, load, seed, expire=0, domain="", path="", timestamp=""):
    """
    Create and return a cookie

    :param name: Cookie name
    :param load: Cookie load
    :param seed: A seed for the HMAC function
    :param expire: Number of minutes before this cookie goes stale
    :param domain: The domain of the cookie
    :param path: The path specification for the cookie
    :param timestamp: A time stamp
    :return: A tuple to be added to headers
    """
    cookie = SimpleCookie()
    if not timestamp:
        timestamp = str(int(time.mktime(time.gmtime())))
    signature = cookie_signature(seed, load, timestamp)
    cookie[name] = "|".join([load, timestamp, signature])
    if path:
        cookie[name]["path"] = path
    if domain:
        cookie[name]["domain"] = domain
    if expire:
        cookie[name]["expires"] = _expiration(expire,
                                              "%a, %d-%b-%Y %H:%M:%S GMT")

    return tuple(cookie.output().split(": ", 1))


def parse_cookie(name, seed, kaka):
    """Parses and verifies a cookie value

    :param seed: A seed used for the HMAC signature
    :param kaka: The cookie
    :return: A tuple consisting of (payload, timestamp)
    """
    if not kaka:
        return None

    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get(name)

    if morsel:
        parts = morsel.value.split("|")
        if len(parts) != 3:
            return None
            # verify the cookie signature
        sig = cookie_signature(seed, parts[0], parts[1])
        if sig != parts[2]:
            raise Exception("Invalid cookie signature")

        try:
            return parts[0].strip(), parts[1]
        except KeyError:
            return None
    else:
        return None


def cookie_parts(name, kaka):
    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get(name)
    if morsel:
        return morsel.value.split("|")
    else:
        return None


def get_post(environ):
    # the environment variable CONTENT_LENGTH may be empty or missing
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0

    # When the method is POST the query string will be sent
    # in the HTTP request body which is passed by the WSGI server
    # in the file like wsgi.input environment variable.
    return environ['wsgi.input'].read(request_body_size)


def get_or_post(environ):
    _method = environ["REQUEST_METHOD"]

    if _method == "GET":
        data = environ.get["QUERY_STRING"]
    elif _method == "POST":
        data = get_post(environ)
    else:
        raise UnsupportedMethod(_method)

    return data


def wsgi_wrapper(environ, start_response, func, **kwargs):
    request = None
    try:
        request = environ["QUERY_STRING"]
    except KeyError:
        pass

    if not request:
        try:
            request = get_post(environ)
        except KeyError:
            pass

    kwargs["request"] = request
    # authentication information
    try:
        kwargs["authn"] = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        pass

    try:
        kwargs["cookie"] = environ["HTTP_COOKIE"]
    except KeyError:
        pass

    # intended audience
    kwargs["requrl"] = geturl(environ)
    kwargs["url"] = geturl(environ, query=False)
    kwargs["baseurl"] = geturl(environ, query=False, path=False)
    kwargs["path"] = getpath(environ)

    resp = func(**kwargs)
    return resp(environ, start_response)


class InvalidCookieSign(Exception):
    pass


class CookieDealer(object):
    def __init__(self, srv, ttl=5):
        self.srv = None
        self.init_srv(srv)
        # minutes before the interaction should be completed
        self.cookie_ttl = ttl  # N minutes
        self.pad_chr = " "

    def init_srv(self, srv):
        if srv:
            self.srv = srv

            for param in ["seed", "iv"]:
                if not getattr(srv, param, None):
                    setattr(srv, param, self.random_string())

    def random_string(self, _size=16):
        """
        Returns a string of random ascii characters or digits

        :param size: The length of the string
        :return: string
        """
        return "".join([random.choice(string.ascii_letters + string.digits) for _ in range(_size)])

    def delete_cookie(self, cookie_name=None):
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        return self.create_cookie("", "", cookie_name=cookie_name, ttl=-1, kill=True)

    def create_cookie(self, value, typ, cookie_name=None, ttl=-1, kill=False, path=""):
        if kill:
            ttl = -1
        elif ttl < 0:
            ttl = self.cookie_ttl
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        timestamp = str(int(time.mktime(time.gmtime())))
        _msg = "::".join([value, timestamp, typ])
        if self.srv.symkey:
            # Pad the message to be multiples of 16 bytes in length
            lm = len(_msg)
            _msg = _msg.ljust(lm + 16 - lm % 16, self.pad_chr)
            info = AESCipher(self.srv.symkey, self.srv.iv).encrypt(_msg)
        else:
            info = _msg
        cookie = make_cookie(cookie_name, info, self.srv.seed,
                             expire=ttl, domain="", path=path)
        return cookie

    def getCookieValue(self, cookie=None, cookie_name=None):
        return self.get_cookie_value(cookie, cookie_name)

    def get_cookie_value(self, cookie=None, cookie_name=None):
        """
        Return information stored in the Cookie

        :param cookie:
        :param cookie_name: The name of the cookie I'm looking for
        :return: tuple (value, timestamp, type)
        """
        if cookie is None or cookie_name is None:
            return None
        else:
            try:
                info, timestamp = parse_cookie(cookie_name,
                                               self.srv.seed, cookie)
                if self.srv.symkey:
                    txt = AESCipher(self.srv.symkey, self.srv.iv).decrypt(info)
                    # strip spaces at the end
                    txt = txt.rstrip(self.pad_chr)
                else:
                    txt = info

                value, _ts, typ = txt.split("::")
                if timestamp == _ts:
                    return value, _ts, typ
            except (TypeError, AssertionError):
                pass
        return None