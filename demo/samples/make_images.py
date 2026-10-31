"""Builds the sample screenshots used by the web app (synthetic, made by the team).

Run from the repo root: python demo/samples/make_images.py   (writes demo/static/samples/*.png)
"""
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parents[1] / "static" / "samples"  # served at /static/samples/


def font(size):
    for name in ("arial.ttf", "DejaVuSans.ttf", "LiberationSans-Regular.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def qr_image(payload: str, px: int) -> Image.Image:
    enc = cv2.QRCodeEncoder.create()
    q = enc.encode(payload)
    q = cv2.resize(q, (px, px), interpolation=cv2.INTER_NEAREST)
    q = cv2.copyMakeBorder(q, 24, 24, 24, 24, cv2.BORDER_CONSTANT, value=255)
    return Image.fromarray(q).convert("RGB")


def chat(lines, sender, qr=None, name="sample.png"):
    """A plain chat-style screenshot: header, one message bubble, optional QR code inside it."""
    w = 720
    f, fb, fs = font(28), font(30), font(22)
    h = 160 + 44 * len(lines) + (420 if qr else 0) + 80
    img = Image.new("RGB", (w, h), (236, 229, 221))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 90], fill=(7, 94, 84))
    d.text((30, 28), sender, fill="white", font=fb)
    top = 130
    bubble_h = 44 * len(lines) + (420 if qr else 0) + 40
    d.rounded_rectangle([24, top, w - 60, top + bubble_h], radius=18, fill="white")
    y = top + 20
    for line in lines:
        d.text((48, y), line, fill=(20, 20, 20), font=f)
        y += 44
    if qr:
        img.paste(qr_image(qr, 340), (48, y + 10))
    d.text((w - 160, top + bubble_h - 34), "10:42 am", fill=(120, 120, 120), font=fs)
    img.save(HERE / name)
    print("wrote", name)


if __name__ == "__main__":
    chat(["Congratulations! Your Amazon refund of", "Rs 5,000 has been approved.",
          "Scan this QR code to receive the money", "in your bank account today."],
         "+91 98765 43210", qr="upi://pay?pa=amazon.refund@ybl&pn=Amazon%20Refund%20Desk&am=4999&cu=INR&tn=Refund",
         name="qr-refund-scam.png")
    chat(["Dear customer, your SBI KYC is pending.", "Pay Rs 10 verification fee to",
          "sbi.kyc.support@okaxis to avoid blocking", "of your account. Reply DONE after paying."],
         "VM-SBIUPD", name="upi-id-scam.png")
    chat(["Your parcel is on hold at customs.", "Scan to pay the delivery charge and", "release it today:"],
         "+91 91234 56789", qr="http://dhl-parcel-release.top/pay", name="qr-link-scam.png")
    chat(["Thanks for shopping at Sharma General Store!", "Scan to pay your bill of Rs 340."],
         "Sharma General Store", qr="upi://pay?pa=sharmastore@okhdfcbank&pn=Sharma%20General%20Store&am=340&cu=INR",
         name="qr-shop-legit.png")
