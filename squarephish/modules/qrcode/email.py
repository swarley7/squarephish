# Copyright 2022 Secureworks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import logging
import pyqrcode  # type: ignore
from configparser import ConfigParser
from email.message import EmailMessage
from email.mime.image import MIMEImage
from PIL import Image
from itertools import product
from squarephish.modules.emailer import Emailer
import io

def split_image(img_bytes):
    # Open the image
    img = Image.open(io.BytesIO(img_bytes))

    # Get the width and height of the image
    width, height = img.size

    # Calculate the midpoint to split the image into two halves
    midpoint = width // 2

    # Crop the image into two halves
    half1 = img.crop((0, 0, midpoint, height))
    half2 = img.crop((midpoint, 0, width, height))
    img_byte_arr1 = io.BytesIO()
    half1.save(img_byte_arr1, format='PNG')
    img_byte_arr2 = io.BytesIO()
    half2.save(img_byte_arr2, format='PNG')
    return img_byte_arr1.getvalue(),img_byte_arr2.getvalue()

class QRCodeEmail:
    """Class to handle initial QR code emails"""

    def _generate_qrcode(
        self,
        server: str,
        port: int,
        endpoint: str,
        email: str,
        url: str,
    ) -> bytes:
        """Generate a QR code for a given URL

        :param server:   malicious server domain/IP
        :param port:     port malicious server is running on
        :param endpoint: malicious server endpoint to request
        :param email:    TO email address of victim
        :param url:      URL if over riding default
        :returns:        QR code raw bytes
        """
        try:
            endpoint = endpoint.strip("/")
            if url is None:
                url = f"https://{server}:{port}/{endpoint}?email={email}"
            qrcode = pyqrcode.create(url)

            # Get the QR code as raw bytes and store as BytesIO object
            qrcode_bytes = io.BytesIO()
            qrcode.png(qrcode_bytes, scale=6)

            
            half1,half2 = split_image(qrcode_bytes.getvalue())
            # Return the QR code bytes
            return half1,half2

        except Exception as e:
            logging.error(f"Error generating QR code: {e}")
            return None

    @classmethod
    def send_qrcode(
        cls,
        email: str,
        config: ConfigParser,
        emailer: Emailer,
        url: str
    ) -> bool:
        """Send initial QR code to victim pointing to our malicious URL

        :param email:   target victim email address to send email to
        :param config:  configuration settings
        :param emailer: emailer object to send emails
        :returns:       bool if the email was successfully sent
        """
        q1,q2 = cls._generate_qrcode(
            cls,
            config.get("EMAIL", "SQUAREPHISH_SERVER"),
            config.get("EMAIL", "SQUAREPHISH_PORT"),
            config.get("EMAIL", "SQUAREPHISH_ENDPOINT"),
            email,
            url,
        )

        if not q1:
            logging.error("Failed to generate QR code")
            return False

        msg = EmailMessage()
        msg["To"] = email
        msg["From"] = config.get("EMAIL", "FROM_EMAIL")
        msg["Subject"] = config.get("EMAIL", "SUBJECT")

        email_template = config.get("EMAIL", "EMAIL_TEMPLATE")
        msg.set_content("", subtype="html")
        msg.add_alternative(email_template, subtype="html")

        # Create a new MIME image to embed into the email as inline
        logo = MIMEImage(q1)
        logo.add_header("Content-ID", f"<q1.png>")  # <img src"cid:qrcode.png">
        logo.add_header("X-Attachment-Id", "q1.png")
        logo["Content-Disposition"] = f"inline; filename=q1.png"
        logo2 = MIMEImage(q2)
        logo2.add_header("Content-ID", f"<q2.png>")  # <img src"cid:qrcode.png">
        logo2.add_header("X-Attachment-Id", "q2.png")
        logo2["Content-Disposition"] = f"inline; filename=q2.png"
        msg.get_payload()[0].make_mixed()
        msg.get_payload()[0].attach(logo)
        msg.get_payload()[0].attach(logo2)
        return emailer.send_email(msg)
