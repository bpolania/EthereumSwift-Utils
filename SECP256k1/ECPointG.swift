//
//  ECPointG.swift
//
//  Created by Boris Polania on 2/19/18.
//  Copyright © 2018 Boris Polania. All rights reserved.
//

import UIKit

class ECPointG: NSObject {
    
    let x   : BDouble
    let y   : BDouble
    let inf : Bool
    
    override
    init() {
        self.x = BDouble("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",radix:16)!
        self.y = BDouble("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",radix:16)!
        self.inf = false
        
        let ecpoint = ECPoint(x:x,y:y)
        let dstep = 4
        var points = [ECPoint]()
        var acc = ecpoint
        points.append(ecpoint)
        
        for i in 1...points.count {
            for _ in 0...dstep {
                
            }
            points[i] = acc
        }
    }
    
    

}
