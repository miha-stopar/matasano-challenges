# Matasano challenges

The first 46 challenges are in Ruby as I wanted to learn the language. For the Bleichenbacher attack (challenges 47 and 48) I switched to Python.

The code is not optimized in any way and is far from being cleaned. I left all sort of unused code in there which I used for debugging.

Besides regular solutions to the challenges, I found the Bleichenbacher attack (challenges 47 and 48) so impressive that I implemented some more recent improvements as well (see below). Wang attack (challenge 55) to find MD4 collisions is also impressive, but the implementation is somehow tiresome.

## Bleichenbacher attack (challenge 48)

In addition to the original Bleichenbacher's attack [2], this implementation contains parallel threads method [3] and trimming and skipping holes technique from [4]. 
While skipping holes is pretty obvious and it is somehow surprising it was not used from the beginning, trimming is really a fascinating improvement over the original attack. 

Note that the results (the number of required oracle calls to decrypt the ciphertext) of this implementation are slightly worse than those reported in [4]. I asked the authors of the paper for the code and tried to reproduce all their features, but the difference was still there (with there code also).
There are two possible explanations - the number of repetitions they used was too small to get a realistic average or I didn't find the optimal configuration (there are many possible configurations for trimmer). I assume the latter even if I tried pretty hard to find it.

I attempted to make some improvements myself, but was unsuccessful except for TTT oracle (see [4]) which is the strongest oracle that probably never appears in a real world (when a message is not conformant, you can compute where outside the conformant interval the message lies), but even here the results were not too significant because the most oracle calls are needed to find s1 where this technique cannot be used.

[1] X. Y. Wang, X. J. Lai, D. G. Feng, H. Chen, X. Y. Yu. Cryptanalysis for Hash Functions MD4 and RIPEMD. Advances in Cryptology–Eurocrypt’05, pp.1-18, Springer-Verlag, May 2005.

[2] D. Bleichenbacher. Chosen ciphertext attacks against protocols based on the RSA encryption standard. In Advances in Cryptology: Proceedings of CRYPTO ’98, volume 1462 of LNCS, pages 1–12, 1998.

[3] T. Rosa V. Klima, O. Pokorny. Attacking RSA-based sessions in SSL/TLS. In 5th International Workshop on Cryptographic Hardware and Embedded Systems (CHES 2003), pages 426 – 440. Springer-Verlag, 2003.

[4] R. Bardou, R. Focardi, Y. Kawamoto, L. Simionato, G. Steel, and J.-K. Tsay. Efficient padding oracle attacks on cryptographic hardware. In CRYPTO, pages 608–625, 2012



